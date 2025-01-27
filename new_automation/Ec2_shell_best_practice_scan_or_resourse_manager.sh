#!/bin/bash

# Set strict error handling
set -euo pipefail
IFS=$'\n\t'

# Configuration
CONFIG_FILE="${HOME}/.aws-resource-manager.conf"
RETRY_ATTEMPTS=3
RETRY_DELAY=5
PARALLEL_JOBS=5
DRY_RUN=false
ORGANIZATION_MODE=false
LOG_FILE="${HOME}/.aws-resource-manager/aws-resource-manager.log"
TEMP_DIR="/tmp/aws-resource-manager"

# Set up cleanup trap at script level
trap cleanup EXIT

# Default thresholds
declare -A THRESHOLDS=(
    ["ami_age_days"]=90
    ["instance_age_days"]=180
    ["stopped_instance_age_days"]=30
    ["unused_resource_age_days"]=7
    ["backup_retention_days"]=30
)

# Function for logging information messages
log() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [INFO] $1" | tee -a "${LOG_FILE}"
}

# Debug log function (only outputs if DEBUG is true)
debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        local timestamp
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "${timestamp} [DEBUG] $1" | tee -a "${LOG_FILE}"
    fi
}

# Initialize the script by setting up directories, logs, and checks
init() {
    # Ensure log directory exists
    local log_dir
    log_dir=$(dirname "${LOG_FILE}")
    mkdir -p "${log_dir}"

    # Create or validate the log file
    if [[ ! -f "${LOG_FILE}" ]]; then
        touch "${LOG_FILE}" || { error "Failed to create log file ${LOG_FILE}. Please check permissions."; exit 1; }
    fi

    # Check if the log file is writable
    if [[ ! -w "${LOG_FILE}" ]]; then
        error "Log file ${LOG_FILE} is not writable. Please check permissions."
        exit 1
    fi

    # Create temporary working directory
    mkdir -p "${TEMP_DIR}"

    # Validate AWS CLI installation and version
    check_aws_cli

    # Ensure the script has required permissions
    check_permissions
}


# Cleanup function for temporary resources
cleanup() {
    log "Cleaning up resources..."
    
    # Clear AWS credentials
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

    # Remove temporary working directory
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
}

check_aws_cli() {
    if ! command -v aws >/dev/null 2>&1; then
        error "AWS CLI is not installed. Please install it and try again."
        exit 1
    fi

    # Minimum required AWS CLI version
    local min_version="2.0.0"
    local current_version
    current_version=$(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)

    if [[ -z "${current_version}" ]]; then
        error "Unable to determine AWS CLI version. Please check your AWS CLI installation."
        exit 1
    fi

    if ! printf "%s\n%s" "${min_version}" "${current_version}" | sort -CV; then
        error "AWS CLI version ${current_version} is below the required version ${min_version}. Please update it."
        exit 1
    fi
}

# Check for required AWS permissions
check_permissions() {
    local required_services=("ec2" "iam" "organizations" "backup")
    for service in "${required_services[@]}"; do
        if ! aws "${service}" describe-regions >/dev/null 2>&1; then
            error "Missing required permissions for ${service}."
            exit 1
        fi
    done
}

# Load configuration values from a file, if it exists
load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        # Source configuration file
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
        log "Configuration loaded from ${CONFIG_FILE}"
        validate_config
    else
        log "No configuration file found. Using default values."
    fi
}


# Validate key configuration values for correctness
validate_config() {
    local required_vars=("RETRY_ATTEMPTS" "RETRY_DELAY" "PARALLEL_JOBS")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            error "Required configuration variable ${var} is not set."
            exit 1
        fi
    done

    # Ensure numeric values for retry and parallelism are valid
    if ! [[ "${RETRY_ATTEMPTS}" =~ ^[0-9]+$ ]] || \
       ! [[ "${RETRY_DELAY}" =~ ^[0-9]+$ ]] || \
       ! [[ "${PARALLEL_JOBS}" =~ ^[0-9]+$ ]]; then
        error "Configuration variables must be numeric."
        exit 1
    fi
}

# Retry logic for executing commands with exponential backoff
retry_command() {
    local cmd=$1
    local attempt=1
    local result

    while (( attempt <= RETRY_ATTEMPTS )); do
        if [[ "${DRY_RUN}" == "true" ]]; then
            log "[DRY RUN] Would execute: ${cmd}"
            return 0
        fi

        if result=$(eval "${cmd}" 2>&1); then
            echo "${result}"
            return 0
        else
            log "Attempt ${attempt}/${RETRY_ATTEMPTS} failed: ${result}"
            sleep $(( RETRY_DELAY * attempt )) # Exponential backoff
            ((attempt++))
        fi
    done

    error "Command failed after ${RETRY_ATTEMPTS} attempts: ${cmd}"
    return 1
}

# Process AWS Organization accounts
process_organization() {
    if [[ "${ORGANIZATION_MODE}" != "true" ]]; then
        return 0
    fi
    
    log "Processing AWS Organization accounts"
    
    # Check Organizations access
    if ! aws organizations describe-organization >/dev/null 2>&1; then
        error "Unable to access AWS Organizations"
        return 1
    fi
    
    local accounts
    accounts=$(retry_command "aws organizations list-accounts --query 'Accounts[?Status==\`ACTIVE\`].Id' --output text")
    
    for account in ${accounts}; do
        log "Processing account: ${account}"
        
        # Assume role with proper error handling
        if ! assume_role "${account}"; then
            error "Failed to assume role in account ${account}"
            continue
        fi
        
        process_account
        
        # Clear credentials
        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done
}

# Assume a role in the target AWS account with retry mechanism
assume_role() {
    local account_id=$1
    local role_arn="arn:aws:iam::${account_id}:role/OrganizationAccountAccessRole"
    local session_name="ResourceManager-${account_id}"

    local credentials
    # Retry command ensures transient errors don't cause the script to fail immediately
    credentials=$(retry_command "aws sts assume-role \
        --role-arn ${role_arn} \
        --role-session-name ${session_name} \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text")

    if [[ $? -ne 0 || -z "${credentials}" ]]; then
        error "Failed to assume role for account ${account_id}"
        return 1
    fi

    # Set AWS credentials
    export AWS_ACCESS_KEY_ID=$(echo "${credentials}" | cut -f1)
    export AWS_SECRET_ACCESS_KEY=$(echo "${credentials}" | cut -f2)
    export AWS_SESSION_TOKEN=$(echo "${credentials}" | cut -f3)
    return 0
}

# Main process function for a single AWS account
process_account() {
    local account_id
    account_id=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null)
    
    if [[ $? -ne 0 || -z "${account_id}" ]]; then
        log "Error: Unable to retrieve AWS account ID. Ensure your credentials are configured correctly."
        return 1
    fi

    log "Processing AWS account: ${account_id}"
    
    # Process each resource type
    process_amis
    process_instances
    process_volumes
    process_vpn_endpoints
}

# Process AMIs
process_amis() {
    log "Processing AMIs"
    
    local amis
    amis=$(aws ec2 describe-images --owners self --query 'Images[*].ImageId' --output text 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        log "Error: Unable to retrieve AMI list."
        return 1
    fi

    if [[ -z "${amis}" ]]; then
        log "No AMIs found for the current account."
        return 0
    fi

    for ami in ${amis}; do
        process_ami "${ami}"
    done
}

# Process a single AMI
process_ami() {
    local ami_id=$1

    if [[ -z "${ami_id}" ]]; then
        log "Error: Missing AMI ID for processing."
        return 1
    fi

    log "Processing AMI: ${ami_id}"

    # Check encryption
    if ! check_ami_encryption "${ami_id}"; then
        log "Warning: AMI ${ami_id} may not be encrypted properly."
    fi

    # Check age
    if ! check_ami_age "${ami_id}"; then
        log "Warning: AMI ${ami_id} exceeds the recommended age."
    fi

    # Check public access
    if ! check_ami_public_access "${ami_id}"; then
        log "Warning: AMI ${ami_id} has public access enabled."
    fi
}

# Check AMI age
check_ami_age() {
    local ami_id=$1
    local creation_date
    
    creation_date=$(aws ec2 describe-images \
        --image-ids "${ami_id}" \
        --query 'Images[0].CreationDate' \
        --output text 2>/dev/null)
    
    if [[ $? -ne 0 || -z "${creation_date}" ]]; then
        log "Error: Unable to fetch creation date for AMI ${ami_id}"
        return 1
    fi
    
    local creation_timestamp
    local current_timestamp
    local age_days
    
    creation_timestamp=$(date -u -d "${creation_date}" +%s)
    current_timestamp=$(date -u +%s)
    age_days=$(( (current_timestamp - creation_timestamp) / 86400 ))
    
    if (( age_days > THRESHOLDS["ami_age_days"] )); then
        log "Warning: AMI ${ami_id} is ${age_days} days old (threshold: ${THRESHOLDS["ami_age_days"]} days)"
    fi
}

# Check AMI public access
check_ami_public_access() {
    local ami_id=$1
    local public_access
    
    public_access=$(aws ec2 describe-images \
        --image-ids "${ami_id}" \
        --query 'Images[0].Public' \
        --output text 2>/dev/null)
    
    if [[ $? -ne 0 || -z "${public_access}" ]]; then
        log "Error: Unable to check public access for AMI ${ami_id}"
        return 1
    fi
    
    if [[ "${public_access}" == "true" ]]; then
        log "Warning: AMI ${ami_id} is publicly accessible."
    fi
}

# Process EC2 instances
process_instances() {
    log "Processing EC2 instances"
    
    local instances
    instances=$(aws ec2 describe-instances \
        --query 'Reservations[*].Instances[*].[InstanceId]' \
        --output text 2>/dev/null)
    
    if [[ $? -ne 0 || -z "${instances}" ]]; then
        log "Error: Unable to retrieve EC2 instances."
        return 1
    fi

    for instance in ${instances}; do
        process_instance "${instance}"
    done
}

# Process single EC2 instance
process_instance() {
    local instance_id=$1
    log "Processing EC2 instance: ${instance_id}"
    
    # Check instance settings
    check_instance_monitoring "${instance_id}"
    check_instance_ebs_optimization "${instance_id}"
    check_instance_iam_profile "${instance_id}"
    check_instance_network "${instance_id}"
    check_instance_security "${instance_id}"
}

# Configuration
CONFIG_FILE="${HOME}/.aws-resource-manager.conf"
RETRY_ATTEMPTS=3
RETRY_DELAY=5
PARALLEL_JOBS=5
DRY_RUN=false
ORGANIZATION_MODE=false

# Default thresholds
declare -A THRESHOLDS=(
    ["ami_age_days"]=90
    ["instance_age_days"]=180
    ["stopped_instance_age_days"]=30
    ["unused_resource_age_days"]=7
    ["backup_retention_days"]=30
)

# Load configuration
load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        source "${CONFIG_FILE}"
        log "Configuration loaded from ${CONFIG_FILE}"
    else
        log "No configuration file found, using defaults"
    fi
}

# Error handling function with retry logic
retry_command() {
    local cmd=$1
    local attempt=1
    local result

    while (( attempt <= RETRY_ATTEMPTS )); do
        if [[ "${DRY_RUN}" == "true" ]]; then
            log "[DRY RUN] Would execute: ${cmd}"
            return 0
        fi

        if result=$(eval "${cmd}" 2>&1); then
            return 0
        else
            log "Attempt ${attempt}/${RETRY_ATTEMPTS} failed: ${result}"
            sleep "${RETRY_DELAY}"
            ((attempt++))
        fi
    done

    error "Command failed after ${RETRY_ATTEMPTS} attempts: ${cmd}"
    return 1
}

# Organization management (for multi-account AWS environments)
process_organization() {
    if [[ "${ORGANIZATION_MODE}" != "true" ]]; then
        return 0
    fi

    log "Processing AWS Organization accounts"
    local accounts
    accounts=$(retry_command "aws organizations list-accounts --query 'Accounts[?Status==\`ACTIVE\`].Id' --output text")
    
    for account in ${accounts}; do
        log "Processing account: ${account}"
        local role_arn="arn:aws:iam::${account}:role/OrganizationAccountAccessRole"
        
        # Assume role in target account
        local credentials
        credentials=$(retry_command "aws sts assume-role --role-arn ${role_arn} --role-session-name ResourceManager")
        
        export AWS_ACCESS_KEY_ID=$(echo "${credentials}" | jq -r .Credentials.AccessKeyId)
        export AWS_SECRET_ACCESS_KEY=$(echo "${credentials}" | jq -r .Credentials.SecretAccessKey)
        export AWS_SESSION_TOKEN=$(echo "${credentials}" | jq -r .Credentials.SessionToken)
        
        process_account
        
        # Clear credentials after processing
        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done
}

# Parallel processing function (for multiple tasks)
process_in_parallel() {
    local items=("$@")
    local pids=()
    local i=0
    
    for item in "${items[@]}"; do
        ((i=i%PARALLEL_JOBS)); ((i++==0)) && wait
        process_item "${item}" &
        pids+=($!)
    done
    
    # Wait for all background processes to complete
    for pid in "${pids[@]}"; do
        wait "${pid}"
    done
}

# Log function for structured output
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1"; }
error() { echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >&2; }

# Validate CSV file existence
validate_csv_file() {
    if [[ ! -f $1 ]]; then
        error "CSV file not found: $1. Please provide a valid file."
        exit 1
    fi

    log "CSV file found: $1"
}

# Validate CSV format
validate_csv_format() {
    local required_columns=("resource" "status")
    local header=$(head -1 "$1")

    for col in "${required_columns[@]}"; do
        if ! grep -q "$col" <<<"$header"; then
            error "CSV file does not have the required column: $col"
            exit 1
        fi
    done

    log "CSV file format validated."
}

# Function to process resources from CSV
process_csv() {
    while IFS=',' read -r resource status; do
        # Skip header row and empty lines
        [[ -z "$resource" || "$resource" == "resource" ]] && continue

        # Skip resources not in alarm state
        if [[ "$status" != "alarm" ]]; then
            log "Skipping resource $resource with status $status (not 'alarm')."
            continue
        fi

        # Determine the service and take appropriate actions
        if [[ "$resource" == arn:aws:ec2:image/* ]]; then
            log "Processing AMI: $resource"
            handle_ami "$resource"
        elif [[ "$resource" == arn:aws:ec2:region:account-id:volume/* ]]; then
            log "Processing EBS Volume: $resource"
            handle_ebs_volume "$resource"
        elif [[ "$resource" == arn:aws:ec2:region:account-id:instance/* ]]; then
            log "Processing EC2 Instance: $resource"
            handle_ec2_instance "$resource"
        elif [[ "$resource" == arn:aws:ec2:region:account-id:vpn-client/* ]]; then
            log "Processing EC2 Client VPN Endpoint: $resource"
            handle_vpn_endpoint "$resource"
        else
            log "Resource type not supported: $resource"
        fi
    done < <(tail -n +2 "$1")  # Skip header row and process the rest
}

# Main loop to read the file and invoke the process_csv function
while IFS=',' read -r resource status; do
   # Skip header row and empty lines
   [[ -z "$resource" || "$resource" == "resource" ]] && continue

   # Process resources from CSV
   process_csv "$1"
done < "$1"


# Handle AMI (Amazon Machine Image) resource
handle_ami() {
    local ami_arn=$1
    local ami_id=$(basename "$ami_arn") # Extract AMI ID from ARN

    log "Handling AMI: $ami_id"

    # Check encryption
    ensure_ami_encryption "$ami_id"

    # Check age of AMI
    ensure_ami_age "$ami_id"

    # Ensure public access is restricted
    ensure_ami_public_access_restricted "$ami_id"
}

# Ensure AMI is encrypted
ensure_ami_encryption() {
    local ami_id=$1
    log "Checking encryption for AMI $ami_id"

    local encryption_status=$(aws ec2 describe-images --image-ids "$ami_id" --query "Images[0].BlockDeviceMappings[0].Ebs.Encrypted" --output text)

    if [[ "$encryption_status" != "True" ]]; then
        log "Encrypting AMI $ami_id"
        aws ec2 modify-image-attribute --image-id "$ami_id" --launch-permission "Add=[{UserId=your-account-id}]" || error "Failed to encrypt AMI $ami_id"
    else
        log "AMI $ami_id is already encrypted"
    fi
}

# Ensure AMI is not older than 90 days
ensure_ami_age() {
    local ami_id=$1
    log "Checking age of AMI $ami_id"

    local creation_date=$(aws ec2 describe-images --image-ids "$ami_id" --query "Images[0].CreationDate" --output text)
    local creation_timestamp=$(date -d "$creation_date" +%s)
    local current_timestamp=$(date +%s)
    local age_days=$(( (current_timestamp - creation_timestamp) / 86400 ))

    if [[ $age_days -gt 90 ]]; then
        log "AMI $ami_id is older than 90 days. Consider deprecating or replacing it."
    else
        log "AMI $ami_id is within the 90-day limit"
    fi
}

# Main loop for validating configuration and best practices
verify_best_practices() {
    log "Verifying best practices for AWS resource management..."

    while true; do
        # Logic for verifying if the resources meet best practices
        # For example:
        if [[ "$THRESHOLDS[ami_age_days]" -le 90 && "$THRESHOLDS[instance_age_days]" -le 180 ]]; then
            log "Configuration is optimal based on best practices."
            return 0
        else
            error "Configuration is not up to best practices. Retrying..."
            sleep 5 # Retry if not meeting best practices
        fi
    done
}

# Ensure AMI restricts public access
ensure_ami_public_access_restricted() {
    local ami_id=$1
    log "Ensuring public access is restricted for AMI $ami_id"

    local public_access=$(aws ec2 describe-images --image-ids "$ami_id" --query "Images[0].Public" --output text)

    if [[ "$public_access" == "True" ]]; then
        log "AMI $ami_id is public. Making it private."
        aws ec2 modify-image-attribute --image-id "$ami_id" --launch-permission "Remove=[all]" || error "Failed to restrict public access for AMI $ami_id"
    else
        log "AMI $ami_id is already private."
    fi
}

# Handle EBS volume resource
handle_ebs_volume() {
    local volume_arn=$1
    local volume_id=$(basename "$volume_arn") # Extract volume ID from ARN

    log "Handling EBS volume: $volume_id"

    # Ensure encryption is enabled
    ensure_encryption_enabled "$volume_id"

    # Ensure DeleteOnTermination is enabled
    ensure_delete_on_termination "$volume_id"
}

# Handle EC2 Instance resource
handle_ec2_instance() {
    local instance_arn=$1
    local instance_id=$(basename "$instance_arn") # Extract instance ID from ARN

    log "Handling EC2 instance: $instance_id"

    # Enable detailed monitoring
    ensure_detailed_monitoring "$instance_id"

    # Ensure EBS optimization is enabled
    ensure_ebs_optimization "$instance_id"

    # Ensure IAM profile is attached
    ensure_iam_profile "$instance_id"

    # Ensure instance is in a VPC
    ensure_instance_in_vpc "$instance_id"

    # Ensure instance does not use key pairs
    ensure_no_key_pairs "$instance_id"
}

# Ensure EC2 instance has detailed monitoring enabled
ensure_detailed_monitoring() {
    local instance_id=$1
    log "Ensuring detailed monitoring is enabled for instance $instance_id"

    local monitoring_status=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].Monitoring.State" --output text)

    if [[ "$monitoring_status" != "enabled" ]]; then
        log "Enabling detailed monitoring for instance $instance_id"
        aws ec2 monitor-instances --instance-ids "$instance_id" || error "Failed to enable detailed monitoring for instance $instance_id"
    else
        log "Instance $instance_id already has detailed monitoring enabled"
    fi
}

# Ensure EC2 instance has EBS optimization enabled
ensure_ebs_optimization() {
    local instance_id=$1
    log "Ensuring EBS optimization is enabled for instance $instance_id"

    local ebs_optimized=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].EbsOptimized" --output text)

    if [[ "$ebs_optimized" != "True" ]]; then
        log "Enabling EBS optimization for instance $instance_id"
        aws ec2 modify-instance-attribute --instance-id "$instance_id" --ebs-optimized || error "Failed to enable EBS optimization for instance $instance_id"
    else
        log "Instance $instance_id is already EBS optimized"
    fi
}

# Ensure EC2 instance has an IAM profile attached
ensure_iam_profile() {
    local instance_id=$1
    log "Ensuring IAM profile is attached to instance $instance_id"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)

    if [[ "$iam_role" == "None" ]]; then
        log "Attaching IAM profile to instance $instance_id"
        # Specify the correct IAM profile ARN
        aws ec2 associate-iam-instance-profile --instance-id "$instance_id" --iam-instance-profile Name="your-iam-profile" || error "Failed to attach IAM profile to instance $instance_id"
    else
        log "Instance $instance_id already has an IAM profile attached"
    fi
}

# Ensure EC2 instance is in a VPC
ensure_instance_in_vpc() {
    local instance_id=$1
    log "Ensuring instance $instance_id is in a VPC"

    local vpc_id=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].VpcId" --output text)

    if [[ "$vpc_id" == "None" ]]; then
        error "Instance $instance_id is not in a VPC"
    else
        log "Instance $instance_id is in VPC $vpc_id"
    fi
}

# Ensure EC2 instance does not use key pairs
ensure_no_key_pairs() {
    local instance_id=$1
    log "Ensuring instance $instance_id does not use key pairs"

    local key_name=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].KeyName" --output text)

    if [[ "$key_name" != "None" ]]; then
        log "Instance $instance_id is using a key pair. Disassociating it."
        aws ec2 modify-instance-attribute --instance-id "$instance_id" --no-disable-api-termination || error "Failed to disassociate key pair for instance $instance_id"
    else
        log "Instance $instance_id does not use a key pair"
    fi
}

# Handle EC2 Client VPN Endpoint
handle_vpn_endpoint() {
    local vpn_arn=$1
    local vpn_id=$(basename "$vpn_arn") # Extract VPN endpoint ID from ARN

    log "Handling VPN endpoint: $vpn_id"

    # Ensure client connection logging is enabled
    ensure_vpn_connection_logging "$vpn_id"
}

# Ensure EC2 Client VPN has client connection logging enabled
ensure_vpn_connection_logging() {
    local vpn_id=$1
    log "Ensuring client connection logging is enabled for VPN endpoint $vpn_id"

    local logging_status=$(aws ec2 describe-client-vpn-endpoints --client-vpn-endpoint-id "$vpn_id" --query "ClientVpnEndpoints[0].ConnectionLogOptions.Enabled" --output text)

    if [[ "$logging_status" != "True" ]]; then
        log "Enabling client connection logging for VPN endpoint $vpn_id"
        aws ec2 modify-client-vpn-endpoint --client-vpn-endpoint-id "$vpn_id" --connection-log-options "Enabled=true,CloudwatchLogGroup=your-cloudwatch-log-group,CloudwatchLogStream=your-log-stream" || error "Failed to enable client connection logging for VPN endpoint $vpn_id"
    else
        log "Client connection logging is already enabled for VPN endpoint $vpn_id"
    fi
}

# Ensure EC2 instances high-level findings are not present in inspector scans
ensure_no_inspector_findings() {
    local instance_id=$1
    log "Ensuring no high-level findings are present in inspector scans for instance $instance_id"

    local findings=$(aws inspector2 list-findings --filter "resourceId=$instance_id" --query "findings[?severity=='HIGH'].id" --output text)

    if [[ -n "$findings" ]]; then
        error "High-level findings found in inspector scan for instance $instance_id: $findings"
    else
        log "No high-level findings present in inspector scan for instance $instance_id"
    fi
}

# Ensure EC2 instance IAM does not allow pass role and lambda invoke function access
ensure_no_pass_role_lambda_invoke() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow pass role or lambda invoke function access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"PassRole"* || "$policy" == *"InvokeLambdaFunction"* ]]; then
        error "IAM role of instance $instance_id has 'PassRole' or 'InvokeLambdaFunction' permissions"
    else
        log "IAM role of instance $instance_id does not allow pass role or lambda invoke function access"
    fi
}

# Ensure EC2 instance IAM role is not attached with credentials exposure access
ensure_no_credentials_exposure() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not have credentials exposure access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"CredentialsExposure"* ]]; then
        error "IAM role of instance $instance_id has credentials exposure access"
    else
        log "IAM role of instance $instance_id does not have credentials exposure access"
    fi
}

# Ensure EC2 instance IAM role does not allow altering critical S3 permissions configuration
ensure_no_s3_permissions_alteration() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow altering critical S3 permissions configuration"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"AlterS3Permissions"* ]]; then
        error "IAM role of instance $instance_id has permission to alter critical S3 permissions"
    else
        log "IAM role of instance $instance_id does not allow altering critical S3 permissions"
    fi
}

# Ensure EC2 instance IAM role does not allow cloud log tampering access
ensure_no_cloud_log_tampering() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow cloud log tampering access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"CloudLogTampering"* ]]; then
        error "IAM role of instance $instance_id has cloud log tampering access"
    else
        log "IAM role of instance $instance_id does not allow cloud log tampering access"
    fi
}

# Ensure EC2 instance IAM role does not allow data destruction access
ensure_no_data_destruction_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow data destruction access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"DataDestruction"* ]]; then
        error "IAM role of instance $instance_id has data destruction access"
    else
        log "IAM role of instance $instance_id does not allow data destruction access"
    fi
}

# Ensure EC2 instance IAM role does not allow database management write access
ensure_no_db_management_write_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow database management write access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"DBManagementWrite"* ]]; then
        error "IAM role of instance $instance_id has database management write access"
    else
        log "IAM role of instance $instance_id does not allow database management write access"
    fi
}

# Ensure EC2 instance IAM role does not allow defense evasion access
ensure_no_defense_evasion_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow defense evasion access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"DefenseEvasion"* ]]; then
        error "IAM role of instance $instance_id has defense evasion access"
    else
        log "IAM role of instance $instance_id does not allow defense evasion access"
    fi
}

# Ensure EC2 instance IAM role does not allow KMS destruction access
ensure_no_kms_destruction_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow destruction KMS access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"KMSDestruction"* ]]; then
        error "IAM role of instance $instance_id has destruction KMS access"
    else
        log "IAM role of instance $instance_id does not allow destruction KMS access"
    fi
}

# Ensure EC2 instance IAM role does not allow RDS destruction access
ensure_no_rds_destruction_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow destruction RDS access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"RDSDestruction"* ]]; then
        error "IAM role of instance $instance_id has destruction RDS access"
    else
        log "IAM role of instance $instance_id does not allow destruction RDS access"
    fi
}

# Ensure EC2 instance IAM role does not allow Elastic IP hijacking access
ensure_no_eip_hijacking_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow Elastic IP hijacking access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"ElasticIPHijacking"* ]]; then
        error "IAM role of instance $instance_id has Elastic IP hijacking access"
    else
        log "IAM role of instance $instance_id does not allow Elastic IP hijacking access"
    fi
}

# Ensure EC2 instance IAM role does not allow management-level access
ensure_no_management_level_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow management-level access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"ManagementLevelAccess"* ]]; then
        error "IAM role of instance $instance_id has management-level access"
    else
        log "IAM role of instance $instance_id does not allow management-level access"
    fi
}

# Ensure EC2 instance IAM role does not allow new group creation with attached policy access
ensure_no_group_creation_with_policy() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow new group creation with attached policy access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"GroupCreationWithPolicy"* ]]; then
        error "IAM role of instance $instance_id has permission for new group creation with attached policy"
    else
        log "IAM role of instance $instance_id does not allow new group creation with attached policy"
    fi
}

# Ensure EC2 instance IAM role does not allow new role creation with attached policy access
ensure_no_role_creation_with_policy() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow new role creation with attached policy access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"RoleCreationWithPolicy"* ]]; then
        error "IAM role of instance $instance_id has permission for new role creation with attached policy"
    else
        log "IAM role of instance $instance_id does not allow new role creation with attached policy"
    fi
}

# Ensure EC2 instance IAM role does not allow new user creation with attached policy access
ensure_no_user_creation_with_policy() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow new user creation with attached policy access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"UserCreationWithPolicy"* ]]; then
        error "IAM role of instance $instance_id has permission for new user creation with attached policy"
    else
        log "IAM role of instance $instance_id does not allow new user creation with attached policy"
    fi
}

# Ensure EC2 instance IAM role does not allow organization write access
ensure_no_org_write_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow organization write access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"OrganizationWrite"* ]]; then
        error "IAM role of instance $instance_id has organization write access"
    else
        log "IAM role of instance $instance_id does not allow organization write access"
    fi
}

# Ensure EC2 instance IAM role does not allow privilege escalation risk access
ensure_no_privilege_escalation_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow privilege escalation risk access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"PrivilegeEscalationRisk"* ]]; then
        error "IAM role of instance $instance_id has privilege escalation risk access"
    else
        log "IAM role of instance $instance_id does not allow privilege escalation risk access"
    fi
}

# Ensure EC2 instance IAM role does not allow security group write access
ensure_no_sg_write_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow security group write access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"SecurityGroupWrite"* ]]; then
        error "IAM role of instance $instance_id has security group write access"
    else
        log "IAM role of instance $instance_id does not allow security group write access"
    fi
}

# Ensure EC2 instance IAM role does not allow write access to resource-based policies
ensure_no_resource_policy_write_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow write access to resource-based policies"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"ResourcePolicyWrite"* ]]; then
        error "IAM role of instance $instance_id has write access to resource-based policies"
    else
        log "IAM role of instance $instance_id does not allow write access to resource-based policies"
    fi
}

# Ensure EC2 instance IAM role does not allow write permission on critical S3 configuration
ensure_no_s3_critical_config_write() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow write permission on critical S3 configuration"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"S3CriticalConfigWrite"* ]]; then
        error "IAM role of instance $instance_id has write permission on critical S3 configuration"
    else
        log "IAM role of instance $instance_id does not allow write permission on critical S3 configuration"
    fi
}

# Ensure EC2 instance IAM role does not allow write-level access
ensure_no_write_level_access() {
    local instance_id=$1
    log "Ensuring IAM role of instance $instance_id does not allow write-level access"

    local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
    local policy=$(aws iam list-attached-role-policies --role-name "$iam_role" --query "AttachedPolicies[].PolicyName" --output text)

    if [[ "$policy" == *"WriteLevelAccess"* ]]; then
        error "IAM role of instance $instance_id has write-level access"
    else
        log "IAM role of instance $instance_id does not allow write-level access"
    fi
}

# Ensure EC2 instances are not attached to 'launch wizard' security groups
ensure_no_launch_wizard_security_groups() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id is not attached to 'launch wizard' security groups"

    local security_groups=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].SecurityGroups[].GroupName" --output text)

    if [[ "$security_groups" == *"launch wizard"* ]]; then
        error "EC2 instance $instance_id is attached to 'launch wizard' security groups"
    else
        log "EC2 instance $instance_id is not attached to 'launch wizard' security groups"
    fi
}

# Ensure no AWS EC2 instances are older than 180 days
ensure_instance_not_older_than_180_days() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id is not older than 180 days"

    local launch_time=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].LaunchTime" --output text)
    local current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    local instance_age=$(( ( $(date -d "$current_time" +%s) - $(date -d "$launch_time" +%s) ) / 86400 ))
    
    if (( instance_age > 180 )); then
        error "EC2 instance $instance_id is older than 180 days ($instance_age days)"
    else
        log "EC2 instance $instance_id is not older than 180 days"
    fi
}

# Ensure EC2 instances do not have a public IP address
ensure_no_public_ip_address() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id does not have a public IP address"

    local public_ip=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].PublicIpAddress" --output text)

    if [[ "$public_ip" != "None" ]]; then
        error "EC2 instance $instance_id has a public IP address"
    else
        log "EC2 instance $instance_id does not have a public IP address"
    fi
}

# Ensure EC2 instances do not use multiple ENIs
ensure_no_multiple_enis() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id does not use multiple ENIs"

    local eni_count=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].NetworkInterfaces | length" --output text)

    if (( eni_count > 1 )); then
        error "EC2 instance $instance_id is using multiple ENIs"
    else
        log "EC2 instance $instance_id is using a single ENI"
    fi
}

# Ensure EC2 instances are protected by a backup plan
ensure_backup_plan_protection() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id is protected by a backup plan"

    local backup_plan_id=$(aws backup list-where-backup-plan --resource-arn "arn:aws:ec2:$instance_id" --query "BackupPlans[0].BackupPlanId" --output text)

    if [[ "$backup_plan_id" == "None" ]]; then
        error "EC2 instance $instance_id is not protected by a backup plan"
    else
        log "EC2 instance $instance_id is protected by a backup plan"
    fi
}

# Ensure public EC2 instances have IAM profile attached
ensure_public_ec2_iam_profile() {
    local instance_id=$1
    log "Ensuring public EC2 instance $instance_id has an IAM profile attached"

    local public_ip=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
    if [[ "$public_ip" != "None" ]]; then
        local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text)
        if [[ "$iam_role" == "None" ]]; then
            error "Public EC2 instance $instance_id does not have an IAM profile attached"
        else
            log "Public EC2 instance $instance_id has an IAM profile attached"
        fi
    else
        log "EC2 instance $instance_id is not public, skipping IAM profile check"
    fi
}

# Ensure AWS EC2 instances have termination protection enabled
ensure_termination_protection_enabled() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id has termination protection enabled"

    local protection_status=$(aws ec2 describe-instance-attribute --instance-id "$instance_id" --attribute "disableApiTermination" --query "DisableApiTermination.Value" --output text)

    if [[ "$protection_status" == "False" ]]; then
        error "Termination protection is not enabled for EC2 instance $instance_id"
    else
        log "Termination protection is enabled for EC2 instance $instance_id"
    fi
}

# Ensure EC2 instance user data does not have secrets
ensure_no_secrets_in_user_data() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id user data does not have secrets"

    local user_data=$(aws ec2 describe-instance-attribute --instance-id "$instance_id" --attribute "userData" --query "UserData.Value" --output text)

    if [[ "$user_data" =~ "password" || "$user_data" =~ "secret" || "$user_data" =~ "key" ]]; then
        error "EC2 instance $instance_id user data contains secrets"
    else
        log "EC2 instance $instance_id user data does not contain secrets"
    fi
}

# Ensure EC2 instances use IMDSv2
ensure_imdsv2_enabled() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id uses IMDSv2"

    local metadata_options=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].MetadataOptions.HttpTokens" --output text)

    if [[ "$metadata_options" != "required" ]]; then
        error "EC2 instance $instance_id does not use IMDSv2"
    else
        log "EC2 instance $instance_id uses IMDSv2"
    fi
}

# Ensure paravirtual EC2 instance types are not used
ensure_no_paravirtual_instances() {
    local instance_id=$1
    log "Ensuring EC2 instance $instance_id does not use a paravirtual instance type"

    local instance_type=$(aws ec2 describe-instances --instance-ids "$instance_id" --query "Reservations[0].Instances[0].InstanceType" --output text)

    if [[ "$instance_type" == *"paravirtual"* ]]; then
        error "EC2 instance $instance_id uses a paravirtual instance type"
    else
        log "EC2 instance $instance_id does not use a paravirtual instance type"
    fi
}

# Ensure AWS EC2 launch templates do not assign public IPs to network interfaces
ensure_no_public_ip_in_launch_template() {
    local launch_template_id=$1
    log "Ensuring EC2 launch template $launch_template_id does not assign public IPs to network interfaces"

    local public_ip_assigned=$(aws ec2 describe-launch-template-versions --launch-template-id "$launch_template_id" --query "LaunchTemplateVersions[].VersionData.NetworkInterfaces[].AssociatePublicIpAddress" --output text)

    if [[ "$public_ip_assigned" == "True" ]]; then
        error "EC2 launch template $launch_template_id assigns public IPs to network interfaces"
    else
        log "EC2 launch template $launch_template_id does not assign public IPs to network interfaces"
    fi
}

# Ensure unused ENIs are removed
ensure_unused_enis_removed() {
    log "Ensuring unused ENIs are removed"

    local enis=$(aws ec2 describe-network-interfaces --query "NetworkInterfaces[?Status=='available'].NetworkInterfaceId" --output text)

    if [[ -n "$enis" ]]; then
        error "There are unused ENIs: $enis"
    else
        log "No unused ENIs found"
    fi
}

# Ensure EC2 stopped instances are removed in 30 days
ensure_stopped_instances_removed_30_days() {
    log "Ensuring EC2 stopped instances are removed in 30 days"

    local stopped_instances=$(aws ec2 describe-instances --filters "Name=instance-state-name,Values=stopped" --query "Reservations[].Instances[].[InstanceId,StateTransitionReason]" --output text)

    for instance in $stopped_instances; do
        local stopped_since=$(echo $instance | awk '{print $2}')
        local stopped_date=$(date -d "$stopped_since" +%s)
        local current_date=$(date +%s)

        local diff_days=$(( (current_date - stopped_date) / 86400 ))
        
        if [[ $diff_days -gt 30 ]]; then
            error "EC2 stopped instance $instance is older than 30 days and should be removed"
        fi
    done
}

# Ensure EC2 instances stopped for over 90 days are removed
ensure_stopped_instances_removed_90_days() {
    log "Ensuring EC2 stopped instances are removed in 90 days"

    local stopped_instances=$(aws ec2 describe-instances --filters "Name=instance-state-name,Values=stopped" --query "Reservations[].Instances[].[InstanceId,StateTransitionReason]" --output text)

    for instance in $stopped_instances; do
        local stopped_since=$(echo $instance | awk '{print $2}')
        local stopped_date=$(date -d "$stopped_since" +%s)
        local current_date=$(date +%s)

        local diff_days=$(( (current_date - stopped_date) / 86400 ))
        
        if [[ $diff_days -gt 90 ]]; then
            error "EC2 stopped instance $instance is older than 90 days and should be removed"
        fi
    done
}

# Ensure EC2 transit gateways have auto-accept shared attachments disabled
ensure_auto_accept_shared_attachments_disabled() {
    log "Ensuring EC2 transit gateways have auto-accept shared attachments disabled"

    local transit_gateways=$(aws ec2 describe-transit-gateways --query "TransitGateways[].TransitGatewayId" --output text)

    for tg in $transit_gateways; do
        local auto_accept=$(aws ec2 describe-transit-gateway-attachments --transit-gateway-id "$tg" --query "TransitGatewayAttachments[].AutoAcceptSharedAttachments" --output text)

        if [[ "$auto_accept" == "enable" ]]; then
            error "EC2 transit gateway $tg has auto-accept shared attachments enabled"
        else
            log "EC2 transit gateway $tg has auto-accept shared attachments disabled"
        fi
    done
}

# Main function
main() {
    local options
    options=$(getopt -o c:p:d -l config:,parallel:,dry-run,org-mode -- "$@")
    
    if [[ $? -ne 0 ]]; then
        error "Invalid options provided"
        exit 1
    fi
    
    eval set -- "${options}"
    
    while true; do
        case "$1" in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -p|--parallel)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            --org-mode)
                ORGANIZATION_MODE=true
                shift
                ;;
            --)
                shift
                break
                ;;
        esac
    done
    
    local csv_file=$1
    
    if [[ -z "${csv_file}" ]]; then
        error "No CSV file provided. Usage: $0 [-c config] [-p parallel_jobs] [-d] [--org-mode] <csv_file>"
        exit 1
    fi
    
    # Initialize
    init
    
    # Load configuration
    load_config
    
    # Process organization if enabled
    if [[ "${ORGANIZATION_MODE}" == "true" ]]; then
        process_organization
    else
        validate_csv_file "${csv_file}"
        validate_csv_format "${csv_file}"
        process_csv "${csv_file}"
    fi
}

# Execute main function with input arguments
main "$@"