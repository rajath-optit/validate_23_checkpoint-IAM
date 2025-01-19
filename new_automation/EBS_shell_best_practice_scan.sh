#!/bin/bash

set -euo pipefail

# Configuration
readonly MAX_RETRIES=3
readonly TIMEOUT_SECONDS=300
readonly VERIFY_ATTEMPTS=30
readonly VERIFY_SLEEP=10
readonly LOG_FILE="changes.log"
readonly REQUIRED_COMMANDS=("aws" "jq" "timeout")
readonly REQUIRED_COLUMNS=("resource" "status")

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Log functions for structured output
log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [${GREEN}INFO${NC}] $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [${YELLOW}WARN${NC}] $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [${RED}ERROR${NC}] $1" | tee -a "$LOG_FILE" >&2
}

# Initialize logging
init_logging() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\n========== Script Started at ${timestamp} ==========\n" >> "$LOG_FILE"
    chmod 600 "$LOG_FILE" 2>/dev/null || true
}

# Validate system requirements
check_requirements() {
    local missing_commands=()
    
    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        error "Missing required commands: ${missing_commands[*]}"
        error "Please install these commands before running the script."
        exit 1
    fi
}

# Validate AWS configuration
validate_aws_config() {
    local aws_region
    aws_region=$(aws configure get region 2>/dev/null) || true
    
    if [[ -z "$aws_region" ]]; then
        error "AWS region not configured. Please run 'aws configure' first."
        exit 1
    }
    
    # Test AWS credentials
    if ! aws sts get-caller-identity &>/dev/null; then
        error "AWS credentials not configured or invalid. Please check your AWS configuration."
        exit 1
    }
    
    log "AWS configuration validated. Using region: $aws_region"
}

# Check required IAM permissions
check_iam_permissions() {
    local required_actions=(
        "ec2:DescribeVolumes"
        "ec2:DescribeInstances"
        "ec2:ModifyInstanceAttribute"
        "ec2:CreateSnapshot"
        "ec2:CreateVolume"
        "ec2:DeleteVolume"
    )
    
    local missing_permissions=()
    for action in "${required_actions[@]}"; do
        if ! aws iam simulate-principal-policy --policy-source-arn "$(aws sts get-caller-identity --query 'Arn' --output text)" \
            --action-names "$action" --query 'EvaluationResults[].EvalDecision' --output text | grep -q "allowed"; then
            missing_permissions+=("$action")
        fi
    done
    
    if [ ${#missing_permissions[@]} -ne 0 ]; then
        warn "Missing IAM permissions: ${missing_permissions[*]}"
        warn "Some operations may fail due to insufficient permissions."
    }
}

# Validate CSV file
validate_csv_file() {
    local csv_file=$1
    
    if [[ ! -f "$csv_file" ]]; then
        error "CSV file not found: $csv_file"
        exit 1
    }
    
    if [[ ! -r "$csv_file" ]]; then
        error "CSV file not readable: $csv_file"
        exit 1
    }
    
    # Check file size
    if [[ ! -s "$csv_file" ]]; then
        error "CSV file is empty: $csv_file"
        exit 1
    }
    
    # Validate CSV format
    local header
    header=$(head -n 1 "$csv_file")
    
    for column in "${REQUIRED_COLUMNS[@]}"; do
        if ! echo "$header" | grep -q "$column"; then
            error "Required column '$column' not found in CSV header"
            exit 1
        fi
    done
    
    log "CSV file validated successfully: $csv_file"
}

# AWS operation with retry logic
aws_operation() {
    local cmd=$1
    local retry=0
    local result
    
    while ((retry < MAX_RETRIES)); do
        if result=$(timeout "$TIMEOUT_SECONDS" bash -c "$cmd" 2>&1); then
            echo "$result"
            return 0
        else
            local exit_code=$?
            if ((exit_code == 124)); then
                error "Operation timed out after $TIMEOUT_SECONDS seconds"
                return 1
            fi
            ((retry++))
            if ((retry < MAX_RETRIES)); then
                warn "Operation failed, retrying ($retry/$MAX_RETRIES)..."
                sleep $((retry * 5))
            fi
        fi
    done
    
    error "Operation failed after $MAX_RETRIES retries: $cmd"
    return 1
}

# Get available volumes
get_available_volumes() {
    aws_operation "aws ec2 describe-volumes --query 'Volumes[*].VolumeId' --output text"
}

# Verify volume state
verify_volume_state() {
    local volume_id=$1
    local expected_state=$2
    local attempt=0
    
    while ((attempt < VERIFY_ATTEMPTS)); do
        local current_state
        current_state=$(aws_operation "aws ec2 describe-volumes --volume-ids $volume_id --query 'Volumes[0].State' --output text")
        
        if [[ "$current_state" == "$expected_state" ]]; then
            return 0
        fi
        
        ((attempt++))
        sleep "$VERIFY_SLEEP"
    done
    
    error "Volume $volume_id did not reach $expected_state state after $VERIFY_ATTEMPTS attempts"
    return 1
}

# Enable DeleteOnTermination
ensure_delete_on_termination() {
    local volume_id=$1
    log "Processing DeleteOnTermination for volume $volume_id"
    
    local instance_id device_name
    instance_id=$(aws_operation "aws ec2 describe-volumes --volume-ids $volume_id --query 'Volumes[0].Attachments[0].InstanceId' --output text")
    device_name=$(aws_operation "aws ec2 describe-volumes --volume-ids $volume_id --query 'Volumes[0].Attachments[0].Device' --output text")
    
    if [[ -z "$instance_id" || -z "$device_name" ]]; then
        warn "Volume $volume_id is not attached to an instance"
        return 0
    fi
    
    local current_value
    current_value=$(aws_operation "aws ec2 describe-instance-attribute --instance-id $instance_id --attribute blockDeviceMapping \
        --query \"BlockDeviceMappings[?DeviceName=='$device_name'].Ebs.DeleteOnTermination\" --output text")
    
    if [[ "$current_value" != "True" ]]; then
        if aws_operation "aws ec2 modify-instance-attribute --instance-id $instance_id --block-device-mappings \
            [{\"DeviceName\": \"$device_name\", \"Ebs\": {\"DeleteOnTermination\": true}}]"; then
            log "Successfully enabled DeleteOnTermination for volume $volume_id"
        else
            error "Failed to enable DeleteOnTermination for volume $volume_id"
            return 1
        fi
    else
        log "DeleteOnTermination already enabled for volume $volume_id"
    fi
}

# Enable encryption
ensure_encryption() {
    local volume_id=$1
    log "Processing encryption for volume $volume_id"
    
    local encryption_status
    encryption_status=$(aws_operation "aws ec2 describe-volumes --volume-ids $volume_id --query 'Volumes[0].Encrypted' --output text")
    
    if [[ "$encryption_status" != "True" ]]; then
        log "Creating encrypted copy of volume $volume_id"
        
        # Create snapshot
        local snapshot_id
        snapshot_id=$(aws_operation "aws ec2 create-snapshot --volume-id $volume_id --description 'Temporary snapshot for encryption' --query 'SnapshotId' --output text")
        
        # Wait for snapshot completion
        if ! verify_volume_state "$snapshot_id" "completed"; then
            error "Failed to create snapshot for volume $volume_id"
            return 1
        fi
        
        # Create encrypted volume
        local new_volume_id
        new_volume_id=$(aws_operation "aws ec2 create-volume --encrypted --snapshot-id $snapshot_id --availability-zone \
            $(aws ec2 describe-volumes --volume-ids $volume_id --query 'Volumes[0].AvailabilityZone' --output text) \
            --query 'VolumeId' --output text")
        
        # Wait for volume creation
        if ! verify_volume_state "$new_volume_id" "available"; then
            error "Failed to create encrypted volume from snapshot"
            return 1
        fi
        
        # Clean up
        aws_operation "aws ec2 delete-snapshot --snapshot-id $snapshot_id"
        
        log "Successfully created encrypted volume $new_volume_id from $volume_id"
    else
        log "Volume $volume_id is already encrypted"
    fi
}

# Process CSV file
process_csv() {
    local csv_file=$1
    local available_volumes
    available_volumes=($(get_available_volumes))
    
    while IFS=, read -r resource status; do
        [[ "$resource" == "resource" ]] && continue
        
        # Clean input
        resource=$(echo "$resource" | tr -d '[:space:]')
        status=$(echo "$status" | tr -d '[:space:]')
        
        # Validate fields
        if [[ -z "$resource" || -z "$status" ]]; then
            warn "Skipping invalid CSV row: empty fields detected"
            continue
        fi
        
        # Extract volume ID
        local volume_id="${resource##*/}"
        
        if [[ "$status" != "alarm" ]]; then
            log "Skipping volume $volume_id: status is not 'alarm'"
            continue
        fi
        
        if [[ ! " ${available_volumes[*]} " =~ " ${volume_id} " ]]; then
            warn "Volume $volume_id not found in current region"
            continue
        }
        
        log "Processing volume $volume_id"
        ensure_delete_on_termination "$volume_id"
        ensure_encryption "$volume_id"
    done < "$csv_file"
}

# Main function
main() {
    if [[ $# -ne 1 ]]; then
        error "Usage: $0 <csv_file>"
        exit 1
    fi
    
    local csv_file=$1
    
    init_logging
    check_requirements
    validate_aws_config
    check_iam_permissions
    validate_csv_file "$csv_file"
    process_csv "$csv_file"
    
    log "Script completed successfully"
}

# Run the script
main "$@"
