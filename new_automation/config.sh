#!/bin/bash

# Configuration file for control mappings
cat > config_controls.yaml << 'EOF'
controls:
  "Config configuration recorder should not fail to deliver logs":
    function: "fix_config_recorder_delivery"
    description: "Ensures AWS Config configuration recorder is successfully delivering logs"
  "AWS Config should be enabled":
    function: "enable_aws_config"
    description: "Ensures AWS Config is enabled in all AWS regions"
EOF

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BLUE='\033[0;34m'

# Arrays to store resources
declare -a need_fix=()
declare -a compliant=()
declare -a not_found=()

# Function to log messages
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    case $level in
        "INFO") echo -e "${BLUE}[$timestamp] INFO: $message${NC}" ;;
        "SUCCESS") echo -e "${GREEN}[$timestamp] SUCCESS: $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}[$timestamp] WARNING: $message${NC}" ;;
        "ERROR") echo -e "${RED}[$timestamp] ERROR: $message${NC}" ;;
        *) echo "[$timestamp] $message" ;;
    esac
}

# Function to check AWS CLI configuration
check_aws_configuration() {
    log "INFO" "Checking AWS CLI configuration..."
    if ! command -v aws &> /dev/null; then
        log "ERROR" "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    if ! aws sts get-caller-identity &> /dev/null; then
        log "ERROR" "AWS CLI is not properly configured. Please run 'aws configure' first."
        exit 1
    fi
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    REGION=$(aws configure get region)
    log "SUCCESS" "AWS CLI configured (Account: $ACCOUNT_ID, Region: $REGION)"
}

# Function to create IAM role for AWS Config if it doesn't exist
create_config_service_role() {
    log "INFO" "Checking for AWS Config service role..."
    
    # Check if AWSConfigRole exists
    if aws iam get-role --role-name AWSConfigRole &>/dev/null; then
        log "SUCCESS" "AWSConfigRole already exists"
        return 0
    fi
    
    log "INFO" "Creating AWSConfigRole for AWS Config..."
    
    # Create the trust policy
    cat > config-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

    # Create the role
    aws iam create-role \
        --role-name AWSConfigRole \
        --assume-role-policy-document file://config-trust-policy.json
    
    # Attach AWS managed policy for AWS Config
    aws iam attach-role-policy \
        --role-name AWSConfigRole \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole
    
    # Clean up the temporary file
    rm -f config-trust-policy.json
    
    log "SUCCESS" "Created AWSConfigRole for AWS Config"
}

# Function to create the S3 bucket for AWS Config if it doesn't exist
create_config_s3_bucket() {
    local bucket_name="config-bucket-$ACCOUNT_ID-$REGION"
    log "INFO" "Checking for AWS Config S3 bucket..."
    
    # Check if the bucket exists
    if aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
        log "SUCCESS" "Config S3 bucket $bucket_name already exists"
    else
        log "INFO" "Creating S3 bucket $bucket_name for AWS Config..."
        
        # Create the bucket
        if [[ "$REGION" == "us-east-1" ]]; then
            aws s3api create-bucket --bucket "$bucket_name"
        else
            aws s3api create-bucket \
                --bucket "$bucket_name" \
                --create-bucket-configuration LocationConstraint="$REGION"
        fi
        
        # Enable bucket versioning for compliance
        aws s3api put-bucket-versioning \
            --bucket "$bucket_name" \
            --versioning-configuration Status=Enabled
        
        # Apply bucket policy
        cat > bucket-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSConfigBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "config.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::$bucket_name"
        },
        {
            "Sid": "AWSConfigBucketDelivery",
            "Effect": "Allow",
            "Principal": {
                "Service": "config.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::$bucket_name/AWSLogs/$ACCOUNT_ID/Config/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
EOF
        
        aws s3api put-bucket-policy \
            --bucket "$bucket_name" \
            --policy file://bucket-policy.json
        
        # Clean up temporary file
        rm -f bucket-policy.json
        
        log "SUCCESS" "Created and configured S3 bucket $bucket_name for AWS Config"
    fi
    
    echo "$bucket_name"
}

# Function to check and fix AWS Config configuration recorder delivery issues
fix_config_recorder_delivery() {
    local region=${1:-$REGION}
    log "INFO" "Checking AWS Config configuration recorder status in region $region..."
    
    # Try to get the configuration recorder status
    local recorder_status
    recorder_status=$(aws configservice describe-configuration-recorder-status \
                      --region "$region" \
                      --query "ConfigurationRecordersStatus[0].recording" \
                      --output text 2>/dev/null)
    
    # If no configuration recorder exists, set up one
    if [[ -z "$recorder_status" || "$recorder_status" == "None" ]]; then
        need_fix+=("Config|$region|No configuration recorder")
        log "WARNING" "No AWS Config configuration recorder found in $region. Setting up..."
        enable_aws_config "$region"
        return
    fi

    if [[ "$recorder_status" == "true" ]]; then
        log "SUCCESS" "AWS Config configuration recorder is active in $region."
    else
        need_fix+=("Config|$region|Configuration recorder not active")
        log "WARNING" "AWS Config configuration recorder is NOT active in $region. Restarting it now..."

        # Get the recorder name
        local recorder_name
        recorder_name=$(aws configservice describe-configuration-recorders \
                        --region "$region" \
                        --query "ConfigurationRecorders[0].name" \
                        --output text)

        # Start the configuration recorder
        aws configservice start-configuration-recorder \
            --configuration-recorder-name "$recorder_name" \
            --region "$region"

        log "SUCCESS" "AWS Config configuration recorder has been restarted in $region."
    fi

    log "INFO" "Verifying AWS Config delivery channel status in $region..."

    # Get the delivery channel details
    local channel_info
    channel_info=$(aws configservice describe-delivery-channels \
                  --region "$region" \
                  --query "DeliveryChannels[0]" \
                  --output json 2>/dev/null)
    
    # If no delivery channel exists, set one up
    if [[ -z "$channel_info" || "$channel_info" == "null" ]]; then
        need_fix+=("Config|$region|No delivery channel")
        log "WARNING" "No AWS Config delivery channel found in $region. Setting up..."
        
        # Create S3 bucket if needed
        local s3_bucket
        s3_bucket=$(create_config_s3_bucket)
        
        # Create the delivery channel
        aws configservice put-delivery-channel \
            --delivery-channel "{\"name\":\"default\",\"s3BucketName\":\"$s3_bucket\",\"configSnapshotDeliveryProperties\":{\"deliveryFrequency\":\"One_Hour\"}}" \
            --region "$region"
        
        log "SUCCESS" "Created AWS Config delivery channel in $region."
    else
        local s3_bucket
        s3_bucket=$(echo "$channel_info" | jq -r '.s3BucketName')
        
        log "INFO" "AWS Config delivery channel is configured to use S3 bucket: $s3_bucket in $region."
        
        # Check if S3 bucket exists and has the right permissions
        if ! aws s3api head-bucket --bucket "$s3_bucket" 2>/dev/null; then
            need_fix+=("Config|$region|S3 bucket not found")
            log "WARNING" "S3 bucket $s3_bucket for AWS Config not found in $region. Creating..."
            
            # Create a new S3 bucket
            local new_bucket
            new_bucket=$(create_config_s3_bucket)
            
            # Update the delivery channel
            aws configservice put-delivery-channel \
                --delivery-channel "{\"name\":\"default\",\"s3BucketName\":\"$new_bucket\",\"configSnapshotDeliveryProperties\":{\"deliveryFrequency\":\"One_Hour\"}}" \
                --region "$region"
            
            log "SUCCESS" "Updated AWS Config delivery channel to use S3 bucket $new_bucket in $region."
        else
            # Check S3 bucket policy
            local s3_policy
            s3_policy=$(aws s3api get-bucket-policy --bucket "$s3_bucket" --query "Policy" --output text 2>/dev/null)
            
            if [[ -z "$s3_policy" ]]; then
                need_fix+=("Config|$region|S3 bucket missing policy")
                log "WARNING" "No policy found for S3 bucket $s3_bucket in $region. Setting required policy..."
                
                # Create bucket policy
                cat > bucket-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSConfigBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "config.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::$s3_bucket"
        },
        {
            "Sid": "AWSConfigBucketDelivery",
            "Effect": "Allow",
            "Principal": {
                "Service": "config.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::$s3_bucket/AWSLogs/$ACCOUNT_ID/Config/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
EOF
                
                aws s3api put-bucket-policy --bucket "$s3_bucket" --policy file://bucket-policy.json
                rm -f bucket-policy.json
                
                log "SUCCESS" "Updated S3 bucket policy for $s3_bucket to allow AWS Config logging."
            else
                log "SUCCESS" "S3 bucket $s3_bucket already has a policy in place."
            }
        fi
    }
    
    # Check the latest status and record the results
    if [[ "$recorder_status" == "true" ]]; then
        compliant+=("Config|$region|Active recorder with delivery configured")
        log "SUCCESS" "AWS Config configuration recorder is active and delivery channel is properly configured in $region."
    else
        # Recheck the status after fixes
        recorder_status=$(aws configservice describe-configuration-recorder-status \
                          --region "$region" \
                          --query "ConfigurationRecordersStatus[0].recording" \
                          --output text 2>/dev/null)
        
        if [[ "$recorder_status" == "true" ]]; then
            compliant+=("Config|$region|Active recorder with delivery configured")
            log "SUCCESS" "AWS Config configuration recorder is now active and delivery channel is properly configured in $region."
        else
            need_fix+=("Config|$region|Failed to activate recorder")
            log "ERROR" "Failed to activate AWS Config configuration recorder in $region even after fixes."
        fi
    fi
}

# Function to enable AWS Config in all regions or a specific region
enable_aws_config() {
    local single_region=$1
    
    if [[ -z "$single_region" ]]; then
        log "INFO" "Checking AWS Config status in all regions..."
        
        # Get list of all enabled AWS regions
        local regions
        regions=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text)
        
        for region in $regions; do
            enable_aws_config_in_region "$region"
        done
    else
        enable_aws_config_in_region "$single_region"
    fi
}

# Function to enable AWS Config in a specific region
enable_aws_config_in_region() {
    local region=$1
    log "INFO" "Checking AWS Config in region: $region"
    
    # Check if AWS Config is enabled
    local config_status
    config_status=$(aws configservice describe-configuration-recorder-status \
                   --region "$region" \
                   --query "ConfigurationRecordersStatus[0].recording" \
                   --output text 2>/dev/null)
    
    if [[ "$config_status" == "true" ]]; then
        compliant+=("Config|$region|Enabled")
        log "SUCCESS" "AWS Config is already enabled in $region."
        return
    fi
    
    need_fix+=("Config|$region|Not enabled")
    log "WARNING" "AWS Config is NOT enabled in $region. Enabling it now..."
    
    # Create IAM role for AWS Config if not exists
    create_config_service_role
    
    # Create S3 bucket for Config if not exists
    local s3_bucket
    s3_bucket=$(create_config_s3_bucket)
    
    # Create configuration recorder
    local role_arn="arn:aws:iam::$ACCOUNT_ID:role/AWSConfigRole"
    aws configservice put-configuration-recorder \
        --region "$region" \
        --configuration-recorder name=default,roleARN="$role_arn",recordingGroup="{allSupported=true,includeGlobalResourceTypes=true}"
    
    # Create delivery channel
    aws configservice put-delivery-channel \
        --region "$region" \
        --delivery-channel "{\"name\":\"default\",\"s3BucketName\":\"$s3_bucket\",\"configSnapshotDeliveryProperties\":{\"deliveryFrequency\":\"One_Hour\"}}"
    
    # Start recording
    aws configservice start-configuration-recorder \
        --region "$region" \
        --configuration-recorder-name default
    
    # Check if Config is now enabled
    config_status=$(aws configservice describe-configuration-recorder-status \
                   --region "$region" \
                   --query "ConfigurationRecordersStatus[0].recording" \
                   --output text 2>/dev/null)
    
    if [[ "$config_status" == "true" ]]; then
        compliant+=("Config|$region|Enabled")
        log "SUCCESS" "AWS Config has been enabled in $region."
    else
        need_fix+=("Config|$region|Failed to enable")
        log "ERROR" "Failed to enable AWS Config in $region."
    fi
}

# Function to process controls from CSV input or run directly
process_controls() {
    local csv_file=$1
    shift
    local selected_controls=("$@")
    
    if [[ -n "$csv_file" && -f "$csv_file" ]]; then
        # Process CSV file
        log "INFO" "Processing controls from CSV file: $csv_file"
        while IFS=, read -r _ _ _ _ control _ _ _ resource region; do
            [[ " ${selected_controls[@]} " =~ " ${control} " ]] || continue
            log "INFO" "Processing control: $control"
            function_name=$(yq eval ".controls.[\"$control\"].function" config_controls.yaml)
            [[ -z "$function_name" ]] && continue
            $function_name "$region"
        done < <(tail -n +2 "$csv_file")
    else
        # Run controls directly
        log "INFO" "Processing selected controls without CSV input"
        for control in "${selected_controls[@]}"; do
            log "INFO" "Processing control: $control"
            function_name=$(yq eval ".controls.[\"$control\"].function" config_controls.yaml)
            [[ -z "$function_name" ]] && continue
            $function_name
        done
    fi
}

# Function to print summary
print_summary() {
    log "INFO" "=== SUMMARY ==="
    
    log "INFO" "Total resources that needed fixes: ${#need_fix[@]}"
    for item in "${need_fix[@]}"; do
        IFS='|' read -r resource_type resource_id issue <<< "$item"
        log "WARNING" "$resource_type $resource_id: $issue"
    done
    
    log "INFO" "Total compliant resources: ${#compliant[@]}"
    for item in "${compliant[@]}"; do
        IFS='|' read -r resource_type resource_id status <<< "$item"
        log "SUCCESS" "$resource_type $resource_id: $status"
    done
    
    log "INFO" "Total resources not found: ${#not_found[@]}"
    for item in "${not_found[@]}"; do
        IFS='|' read -r resource_type resource_id <<< "$item"
        log "ERROR" "$resource_type $resource_id: Not found"
    done
}

# Main function
main() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 [csv_file] <control1> [control2 ...]"
        echo "Available controls:"
        yq eval '.controls | keys' config_controls.yaml
        exit 1
    fi
    
    # Check AWS CLI and YQ
    check_aws_configuration
    if ! command -v yq &> /dev/null; then
        log "WARNING" "YQ is not installed. This is required for processing YAML files."
        log "INFO" "You can install it with: pip install yq"
        exit 1
    fi
    
    # Process controls
    process_controls "$@"
    
    # Print summary
    print_summary
    
    log "SUCCESS" "AWS Config automation completed."
}

main "$@"
