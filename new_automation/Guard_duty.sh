#!/bin/bash

# Configuration file for GuardDuty control mappings
cat > guardduty_control_mappings.yaml << 'EOF'
controls:
  "GuardDuty findings should be archived":
    function: "ensure_findings_archived"
    description: "Ensures GuardDuty findings are archived based on defined criteria"
  "GuardDuty Detector should be centrally configured":
    function: "ensure_central_configuration"
    description: "Ensures GuardDuty is centrally managed across AWS Organization"
  "GuardDuty should be enabled":
    function: "ensure_guardduty_enabled"
    description: "Ensures GuardDuty is enabled in all AWS regions"
  "GuardDuty Detector should not have high severity findings":
    function: "ensure_no_high_severity_findings"
    description: "Ensures there are no high severity findings in GuardDuty"
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

# Function to get all AWS regions
get_all_regions() {
    aws ec2 describe-regions --query "Regions[].RegionName" --output text
}

# Function to check if GuardDuty is enabled in a region
is_guardduty_enabled() {
    local region=$1
    local detector_id=$(aws guardduty list-detectors --region "$region" --query "DetectorIds[0]" --output text 2>/dev/null)
    if [[ -z "$detector_id" || "$detector_id" == "None" ]]; then
        return 1
    else
        local detector_status=$(aws guardduty get-detector --region "$region" --detector-id "$detector_id" --query "Status" --output text 2>/dev/null)
        if [[ "$detector_status" == "ENABLED" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

# Function to ensure GuardDuty is enabled in all regions
ensure_guardduty_enabled() {
    local region_param=$1
    local regions

    if [[ -n "$region_param" && "$region_param" != "all" ]]; then
        regions="$region_param"
    else
        regions=$(get_all_regions)
    fi

    log "INFO" "Checking GuardDuty status in specified regions..."
    
    for region in $regions; do
        log "INFO" "Checking GuardDuty in region: $region"
        
        if is_guardduty_enabled "$region"; then
            compliant+=("GuardDuty|$region|Enabled")
            log "SUCCESS" "GuardDuty is already enabled in $region"
        else
            need_fix+=("GuardDuty|$region|Not enabled")
            log "WARNING" "GuardDuty is NOT enabled in $region. Enabling it now..."
            
            # Enable GuardDuty
            local detector_id=$(aws guardduty create-detector --region "$region" --enable --finding-publishing-frequency FIFTEEN_MINUTES --query "DetectorId" --output text)
            
            if [[ -n "$detector_id" && "$detector_id" != "None" ]]; then
                compliant+=("GuardDuty|$region|Enabled")
                log "SUCCESS" "GuardDuty has been enabled in $region with Detector ID: $detector_id"
            else
                log "ERROR" "Failed to enable GuardDuty in $region"
            fi
        fi
    done
}

# Function to ensure GuardDuty findings are archived based on criteria
ensure_findings_archived() {
    local region_param=$1
    local age_days=${2:-7}  # Default to 7 days if not specified
    local severity=${3:-5}  # Default to severity below 5 if not specified
    local regions

    if [[ -n "$region_param" && "$region_param" != "all" ]]; then
        regions="$region_param"
    else
        regions=$(get_all_regions)
    fi

    log "INFO" "Checking GuardDuty findings for archiving criteria..."
    
    for region in $regions; do
        if ! is_guardduty_enabled "$region"; then
            log "WARNING" "GuardDuty is not enabled in $region. Skipping findings check."
            continue
        fi
        
        log "INFO" "Processing findings in region: $region"
        
        # Get detector ID
        local detector_id=$(aws guardduty list-detectors --region "$region" --query "DetectorIds[0]" --output text)
        
        # Get findings older than specified days
        local cutoff_date=$(date -d "-${age_days} days" +"%Y-%m-%dT%H:%M:%S.000Z")
        local findings=$(aws guardduty list-findings --region "$region" --detector-id "$detector_id" --finding-criteria "{\"Criterion\":{\"updatedAt\":{\"Lt\":[\"$cutoff_date\"]}}}" --query "FindingIds" --output text)
        
        # Get low severity findings
        local low_severity_findings=$(aws guardduty list-findings --region "$region" --detector-id "$detector_id" --finding-criteria "{\"Criterion\":{\"severity\":{\"Lt\":[$severity]}}}" --query "FindingIds" --output text)
        
        # Combine findings to archive
        local all_findings="$findings $low_severity_findings"
        all_findings=$(echo $all_findings | tr ' ' '\n' | sort | uniq | tr '\n' ' ')
        
        if [[ -z "$all_findings" ]]; then
            compliant+=("GuardDuty|$region|No findings to archive")
            log "SUCCESS" "No GuardDuty findings in $region meet the archiving criteria"
        else
            need_fix+=("GuardDuty|$region|Findings need archiving")
            log "WARNING" "Found GuardDuty findings in $region that should be archived. Archiving now..."
            
            # Archive findings
            aws guardduty archive-findings --region "$region" --detector-id "$detector_id" --finding-ids $all_findings
            
            if [ $? -eq 0 ]; then
                compliant+=("GuardDuty|$region|Findings archived")
                log "SUCCESS" "Successfully archived GuardDuty findings in $region"
            else
                log "ERROR" "Failed to archive GuardDuty findings in $region"
            fi
        fi
    done
}

# Function to ensure GuardDuty is centrally configured across the organization
ensure_central_configuration() {
    local central_region=${1:-$REGION}  # Default to current region if not specified
    
    log "INFO" "Checking if GuardDuty is centrally configured across the organization..."
    
    # Check if Organizations is available
    local is_org_available
    is_org_available=$(aws organizations describe-organization 2>/dev/null && echo "true" || echo "false")
    
    if [[ "$is_org_available" == "false" ]]; then
        log "WARNING" "AWS Organizations is not available or not configured. Cannot set up central configuration."
        return 1
    fi
    
    # Check if GuardDuty is enabled in the central region
    if ! is_guardduty_enabled "$central_region"; then
        log "WARNING" "GuardDuty is not enabled in the central region: $central_region. Enabling it now..."
        ensure_guardduty_enabled "$central_region"
    fi
    
    # Get detector ID in the central region
    local central_detector_id=$(aws guardduty list-detectors --region "$central_region" --query "DetectorIds[0]" --output text)
    
    log "INFO" "Using detector ID $central_detector_id in $central_region as central configuration"
    
    # Check if Organization auto-enable is configured
    local auto_enable_status=$(aws guardduty describe-organization-configuration --region "$central_region" --detector-id "$central_detector_id" --query "AutoEnable" --output text 2>/dev/null || echo "ERROR")
    
    if [[ "$auto_enable_status" == "ERROR" || "$auto_enable_status" == "NONE" ]]; then
        need_fix+=("GuardDuty|$central_region|Auto-enable not configured")
        log "WARNING" "GuardDuty auto-enable is not configured for the organization. Configuring now..."
        
        # Enable organization admin account
        aws guardduty enable-organization-admin-account --region "$central_region" --admin-account-id "$ACCOUNT_ID"
        
        # Configure auto-enable
        aws guardduty update-organization-configuration --region "$central_region" --detector-id "$central_detector_id" --auto-enable
        
        if [ $? -eq 0 ]; then
            compliant+=("GuardDuty|$central_region|Auto-enable configured")
            log "SUCCESS" "Successfully configured GuardDuty auto-enable for the organization"
        else
            log "ERROR" "Failed to configure GuardDuty auto-enable for the organization"
        fi
    else
        compliant+=("GuardDuty|$central_region|Auto-enable configured")
        log "SUCCESS" "GuardDuty auto-enable is already configured for the organization"
    fi
    
    # Get all organization member accounts
    local member_accounts=$(aws organizations list-accounts --query "Accounts[?Status=='ACTIVE'].Id" --output text)
    
    for account in $member_accounts; do
        if [[ "$account" == "$ACCOUNT_ID" ]]; then
            continue  # Skip admin account
        fi
        
        log "INFO" "Checking GuardDuty status for account: $account"
        
        # Check if account is a GuardDuty member
        local member_status=$(aws guardduty list-members --region "$central_region" --detector-id "$central_detector_id" --query "Members[?AccountId=='$account'].RelationshipStatus" --output text)
        
        if [[ -z "$member_status" || "$member_status" != "Enabled" ]]; then
            need_fix+=("GuardDuty|$account|Not a member")
            log "WARNING" "Account $account is not a GuardDuty member. Adding now..."
            
            # Get account email
            local account_email=$(aws organizations describe-account --account-id "$account" --query "Account.Email" --output text)
            
            # Create member
            aws guardduty create-members --region "$central_region" --detector-id "$central_detector_id" --account-details "[{\"AccountId\":\"$account\",\"Email\":\"$account_email\"}]"
            
            # Invite member
            aws guardduty invite-members --region "$central_region" --detector-id "$central_detector_id" --account-ids "$account"
            
            if [ $? -eq 0 ]; then
                compliant+=("GuardDuty|$account|Member added")
                log "SUCCESS" "Successfully added account $account as a GuardDuty member"
            else
                log "ERROR" "Failed to add account $account as a GuardDuty member"
            fi
        else
            compliant+=("GuardDuty|$account|Member")
            log "SUCCESS" "Account $account is already a GuardDuty member"
        fi
    done
}

# Function to ensure no high severity findings
ensure_no_high_severity_findings() {
    local region_param=$1
    local severity_threshold=${2:-7}  # Default to 7.0 if not specified
    local regions
    local high_severity_count=0

    if [[ -n "$region_param" && "$region_param" != "all" ]]; then
        regions="$region_param"
    else
        regions=$(get_all_regions)
    fi

    log "INFO" "Checking for high-severity GuardDuty findings (severity >= $severity_threshold)..."
    
    for region in $regions; do
        if ! is_guardduty_enabled "$region"; then
            log "WARNING" "GuardDuty is not enabled in $region. Skipping findings check."
            continue
        }
        
        log "INFO" "Checking findings in region: $region"
        
        # Get detector ID
        local detector_id=$(aws guardduty list-detectors --region "$region" --query "DetectorIds[0]" --output text)
        
        # Get high-severity findings
        local findings=$(aws guardduty list-findings --region "$region" --detector-id "$detector_id" --finding-criteria "{\"Criterion\":{\"severity\":{\"Gte\":[$severity_threshold]}}}" --query "FindingIds" --output text)
        
        if [[ -z "$findings" ]]; then
            compliant+=("GuardDuty|$region|No high severity findings")
            log "SUCCESS" "No high-severity GuardDuty findings in $region"
        else
            need_fix+=("GuardDuty|$region|Has high severity findings")
            log "WARNING" "High-severity GuardDuty findings detected in $region"
            ((high_severity_count++))
            
            # Get details about findings for reporting
            local findings_array=($findings)
            for finding_id in "${findings_array[@]}"; do
                local finding_details=$(aws guardduty get-findings --region "$region" --detector-id "$detector_id" --finding-ids "$finding_id" --query "Findings[0].[Title,Severity,Type]" --output text)
                log "WARNING" "High Severity Finding: $finding_details"
            done
            
            # Send SNS notification if configured
            if [[ -n "$SNS_TOPIC_ARN" ]]; then
                log "INFO" "Sending notification to SNS topic: $SNS_TOPIC_ARN"
                aws sns publish --region "$region" --topic-arn "$SNS_TOPIC_ARN" \
                    --message "High-severity GuardDuty findings detected in $region: $findings" \
                    --subject "GuardDuty Alert: High-Severity Findings Detected"
            fi
        fi
    done
    
    if [[ $high_severity_count -gt 0 ]]; then
        log "WARNING" "$high_severity_count regions have high-severity GuardDuty findings"
    else
        log "SUCCESS" "No high-severity GuardDuty findings detected in any region"
    fi
}

# Function to process CSV input
process_csv() {
    local csv_file=$1
    shift
    local selected_controls=("$@")
    while IFS=, read -r _ _ _ _ control _ _ _ resource _; do
        [[ " ${selected_controls[@]} " =~ " ${control} " ]] || continue
        log "INFO" "Processing control: $control"
        local function_name=$(yq eval ".controls.[\"$control\"].function" guardduty_control_mappings.yaml)
        [[ -z "$function_name" ]] && continue
        local region=$(echo $resource | grep -oE 'eu-[a-z]+-[0-9]+|us-[a-z]+-[0-9]+|ap-[a-z]+-[0-9]+|sa-[a-z]+-[0-9]+|ca-[a-z]+-[0-9]+|me-[a-z]+-[0-9]+|af-[a-z]+-[0-9]+' || echo "$REGION")
        $function_name "$region"
    done < <(tail -n +2 "$csv_file")
}

# Function to display final summary
display_summary() {
    log "INFO" "=== GuardDuty Compliance Summary ==="
    log "INFO" "Total resources checked: $((${#need_fix[@]} + ${#compliant[@]} + ${#not_found[@]}))"
    log "SUCCESS" "Compliant: ${#compliant[@]}"
    log "WARNING" "Non-compliant (fixed): ${#need_fix[@]}"
    log "ERROR" "Not found: ${#not_found[@]}"
    
    if [[ ${#compliant[@]} -gt 0 ]]; then
        log "INFO" "=== Compliant Resources ==="
        for item in "${compliant[@]}"; do
            IFS='|' read -r resource_type resource_id status <<< "$item"
            log "SUCCESS" "$resource_type: $resource_id - $status"
        done
    fi
    
    if [[ ${#need_fix[@]} -gt 0 ]]; then
        log "INFO" "=== Fixed Resources ==="
        for item in "${need_fix[@]}"; do
            IFS='|' read -r resource_type resource_id status <<< "$item"
            log "WARNING" "$resource_type: $resource_id - $status"
        done
    fi
    
    if [[ ${#not_found[@]} -gt 0 ]]; then
        log "INFO" "=== Not Found Resources ==="
        for item in "${not_found[@]}"; do
            IFS='|' read -r resource_type resource_id <<< "$item"
            log "ERROR" "$resource_type: $resource_id"
        done
    fi
}

# Function to display help information
display_help() {
    echo "AWS GuardDuty Compliance and Remediation Script"
    echo ""
    echo "Usage: $0 [options] [commands]"
    echo ""
    echo "Options:"
    echo "  -h, --help             Display this help message"
    echo "  -r, --region REGION    Specify AWS region (default: configured region)"
    echo "  -a, --all-regions      Run on all AWS regions"
    echo "  -s, --sns-topic ARN    Specify SNS topic ARN for notifications"
    echo "  -c, --csv FILE         Process controls from CSV file"
    echo ""
    echo "Commands:"
    echo "  enable                  Enable GuardDuty in specified region(s)"
    echo "  archive [days] [sev]    Archive findings older than [days] days (default: 7) and below severity [sev] (default: 5)"
    echo "  central [region]        Configure central management in [region] (default: configured region)"
    echo "  findings [sev]          Check for high severity findings (above [sev], default: 7)"
    echo "  check-all               Run all checks"
    echo ""
    echo "Examples:"
    echo "  $0 -r us-east-1 enable                      # Enable GuardDuty in us-east-1"
    echo "  $0 -a archive 14 3                         # Archive findings in all regions older than 14 days with severity below 3"
    echo "  $0 -c findings.csv \"GuardDuty should be enabled\" # Check specified control from CSV file"
    echo "  $0 check-all                               # Run all checks in configured region"
}

# Main function
main() {
    # Check if no arguments were provided
    if [[ $# -eq 0 ]]; then
        display_help
        exit 0
    fi

    # Parse command line arguments
    REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
    CHECK_ALL_REGIONS=false
    SNS_TOPIC_ARN=""
    CSV_FILE=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                display_help
                exit 0
                ;;
            -r|--region)
                REGION="$2"
                shift 2
                ;;
            -a|--all-regions)
                CHECK_ALL_REGIONS=true
                shift
                ;;
            -s|--sns-topic)
                SNS_TOPIC_ARN="$2"
                shift 2
                ;;
            -c|--csv)
                CSV_FILE="$2"
                shift 2
                ;;
            enable)
                COMMAND="enable"
                shift
                ;;
            archive)
                COMMAND="archive"
                ARCHIVE_DAYS=${2:-7}
                ARCHIVE_SEVERITY=${3:-5}
                shift
                [[ $1 =~ ^[0-9]+$ ]] && shift
                [[ $1 =~ ^[0-9]+$ ]] && shift
                ;;
            central)
                COMMAND="central"
                CENTRAL_REGION=${2:-$REGION}
                shift
                [[ $2 =~ ^[a-z]+-[a-z]+-[0-9]+$ ]] && shift
                ;;
            findings)
                COMMAND="findings"
                SEVERITY_THRESHOLD=${2:-7}
                shift
                [[ $1 =~ ^[0-9]+$ ]] && shift
                ;;
            check-all)
                COMMAND="check-all"
                shift
                ;;
            *)
                if [[ -n "$CSV_FILE" && -f "$CSV_FILE" ]]; then
                    SELECTED_CONTROLS+=("$1")
                else
                    echo "Unknown option: $1"
                    display_help
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Verify AWS CLI configuration
    check_aws_configuration
    
    # Determine which regions to check
    if [[ "$CHECK_ALL_REGIONS" == "true" ]]; then
        TARGET_REGION="all"
    else
        TARGET_REGION="$REGION"
    fi
    
    # Process commands
    if [[ -n "$CSV_FILE" && ${#SELECTED_CONTROLS[@]} -gt 0 ]]; then
        # Process CSV file with selected controls
        process_csv "$CSV_FILE" "${SELECTED_CONTROLS[@]}"
    else
        # Process direct commands
        case $COMMAND in
            enable)
                ensure_guardduty_enabled "$TARGET_REGION"
                ;;
            archive)
                ensure_findings_archived "$TARGET_REGION" "$ARCHIVE_DAYS" "$ARCHIVE_SEVERITY"
                ;;
            central)
                ensure_central_configuration "$CENTRAL_REGION"
                ;;
            findings)
                ensure_no_high_severity_findings "$TARGET_REGION" "$SEVERITY_THRESHOLD"
                ;;
            check-all)
                ensure_guardduty_enabled "$TARGET_REGION"
                ensure_findings_archived "$TARGET_REGION"
                ensure_central_configuration "$REGION"
                ensure_no_high_severity_findings "$TARGET_REGION"
                ;;
            *)
                log "ERROR" "No valid command specified"
                display_help
                exit 1
                ;;
        esac
    fi
    
    # Display summary
    display_summary
}

# Execute main function
main "$@"
