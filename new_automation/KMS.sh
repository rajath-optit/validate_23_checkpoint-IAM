#!/bin/bash

# Configuration file for KMS control mappings
cat > kms_control_mappings.yaml << 'EOF'
controls:
  "KMS CMK rotation should be enabled":
    function: "ensure_kms_rotation"
    description: "Ensures all KMS Customer Managed Keys have key rotation enabled"
  "KMS keys should be in use":
    function: "ensure_kms_in_use"
    description: "Ensures KMS keys are actively being used"
  "KMS CMK policies should prohibit public access":
    function: "ensure_kms_no_public_access"
    description: "Ensures KMS key policies do not allow public access"
  "KMS key decryption should be restricted in IAM inline policy":
    function: "ensure_kms_restricted_inline_policy"
    description: "Ensures IAM inline policies restrict KMS key decryption"
  "KMS keys should not be pending deletion":
    function: "ensure_kms_not_pending_deletion"
    description: "Ensures KMS keys are not scheduled for deletion"
  "KMS key decryption should be restricted in IAM customer managed policy":
    function: "ensure_kms_restricted_managed_policy"
    description: "Ensures customer managed IAM policies restrict KMS key decryption"
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

# Function to validate AWS resources
validate_resource() {
    local resource_id=$1
    local resource_type=$2
    case $resource_type in
        "key") aws kms describe-key --key-id "$resource_id" &>/dev/null && return 0 ;;
        "policy") aws iam get-policy --policy-arn "$resource_id" &>/dev/null && return 0 ;;
        "role") aws iam get-role --role-name "$resource_id" &>/dev/null && return 0 ;;
    esac
    return 1
}

# Function to enable key rotation for KMS CMKs
ensure_kms_rotation() {
    local key_id=$1
    log "INFO" "Checking if key rotation is enabled for KMS key: $key_id"
    
    if ! validate_resource "$key_id" "key"; then
        not_found+=("KMS Key|$key_id")
        log "ERROR" "KMS key $key_id not found"
        return 1
    fi
    
    # Check if key is a customer managed key (not AWS managed)
    local key_manager
    key_manager=$(aws kms describe-key --key-id "$key_id" --query "KeyMetadata.KeyManager" --output text)
    
    if [[ "$key_manager" != "CUSTOMER" ]]; then
        log "INFO" "Key $key_id is an AWS managed key. Rotation is managed by AWS."
        compliant+=("KMS Key|$key_id|AWS managed rotation")
        return 0
    fi
    
    # Check key rotation status
    local rotation_status
    rotation_status=$(aws kms get-key-rotation-status --key-id "$key_id" --query "KeyRotationEnabled" --output text 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to check key rotation status for $key_id"
        return 1
    fi
    
    if [[ "$rotation_status" == "False" ]]; then
        need_fix+=("KMS Key|$key_id|Rotation disabled")
        log "WARNING" "Key rotation is not enabled for KMS key $key_id. Enabling now..."
        
        # Enable key rotation
        aws kms enable-key-rotation --key-id "$key_id"
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Key rotation enabled for KMS key $key_id"
            compliant+=("KMS Key|$key_id|Rotation enabled")
        else
            log "ERROR" "Failed to enable key rotation for KMS key $key_id"
        fi
    else
        compliant+=("KMS Key|$key_id|Rotation enabled")
        log "SUCCESS" "Key rotation is already enabled for KMS key $key_id"
    fi
}

# Function to check if KMS keys are in use
ensure_kms_in_use() {
    local key_id=$1
    log "INFO" "Checking if KMS key $key_id is in use..."
    
    if ! validate_resource "$key_id" "key"; then
        not_found+=("KMS Key|$key_id")
        log "ERROR" "KMS key $key_id not found"
        return 1
    fi
    
    # Check for recent usage (last 90 days)
    local current_date=$(date +%s)
    local ninety_days_ago=$(date -d "90 days ago" +%Y-%m-%d)
    
    local usage
    usage=$(aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=ResourceName,AttributeValue="$key_id" \
        --start-time "$ninety_days_ago" \
        --query "Events[?contains(Resources[].ResourceName, '$key_id')].EventName" \
        --output text)
    
    if [[ -z "$usage" ]]; then
        need_fix+=("KMS Key|$key_id|Not in use")
        log "WARNING" "KMS key $key_id has not been used in the last 90 days"
        
        # Get key alias if it exists
        local alias
        alias=$(aws kms list-aliases --key-id "$key_id" --query "Aliases[0].AliasName" --output text)
        if [[ "$alias" == "None" ]]; then
            alias="No alias found"
        fi
        
        # Suggest deprecation plan
        log "INFO" "Suggested actions for unused key $key_id ($alias):"
        log "INFO" "1. Verify if this key is needed for backup or archived data"
        log "INFO" "2. If not needed, consider scheduling it for deletion"
        log "INFO" "3. Document the decision for compliance purposes"
    else
        compliant+=("KMS Key|$key_id|In use")
        log "SUCCESS" "KMS key $key_id is actively in use"
    fi
}

# Function to ensure KMS CMK policies prohibit public access
ensure_kms_no_public_access() {
    local key_id=$1
    log "INFO" "Checking if KMS key $key_id has public access..."
    
    if ! validate_resource "$key_id" "key"; then
        not_found+=("KMS Key|$key_id")
        log "ERROR" "KMS key $key_id not found"
        return 1
    fi
    
    # Get the key policy
    local policy
    policy=$(aws kms get-key-policy --key-id "$key_id" --policy-name "default" --output json)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to retrieve key policy for $key_id"
        return 1
    fi
    
    # Check for public access (Principal: "*" or Principal.AWS: "*")
    local has_public_access=false
    if echo "$policy" | jq -e '.Statement[] | select(.Principal=="*" or .Principal.AWS=="*")' > /dev/null; then
        has_public_access=true
    fi
    
    if $has_public_access; then
        need_fix+=("KMS Key|$key_id|Public access")
        log "WARNING" "KMS key $key_id has public access in its policy. Fixing..."
        
        # Make a copy of the policy
        local new_policy
        new_policy=$(echo "$policy" | jq '.Statement = [.Statement[] | select(.Principal!="*" and .Principal.AWS!="*")]')
        
        # Apply the updated policy
        echo "$new_policy" > temp_policy.json
        aws kms put-key-policy --key-id "$key_id" --policy-name "default" --policy file://temp_policy.json
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Public access removed from KMS key $key_id policy"
            rm temp_policy.json
            compliant+=("KMS Key|$key_id|No public access")
        else
            log "ERROR" "Failed to update key policy for $key_id"
            rm temp_policy.json
        fi
    else
        compliant+=("KMS Key|$key_id|No public access")
        log "SUCCESS" "KMS key $key_id does not have public access"
    fi
}

# Function to ensure KMS key decryption is restricted in IAM inline policies
ensure_kms_restricted_inline_policy() {
    local role_name=$1
    log "INFO" "Checking if IAM role $role_name has unrestricted KMS decryption in inline policies..."
    
    if ! validate_resource "$role_name" "role"; then
        not_found+=("IAM Role|$role_name")
        log "ERROR" "IAM role $role_name not found"
        return 1
    fi
    
    # Get inline policies for the role
    local policies
    policies=$(aws iam list-role-policies --role-name "$role_name" --query "PolicyNames" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to list inline policies for role $role_name"
        return 1
    fi
    
    local unrestricted_found=false
    for policy in $policies; do
        log "INFO" "Checking inline policy: $policy"
        
        # Get policy document
        local policy_doc
        policy_doc=$(aws iam get-role-policy --role-name "$role_name" --policy-name "$policy" --query "PolicyDocument" --output json)
        
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to get policy document for $policy"
            continue
        fi
        
        # Check for unrestricted KMS decrypt permissions
        if echo "$policy_doc" | jq -e '.Statement[] | select(.Effect=="Allow" and (.Action=="kms:Decrypt" or .Action[]=="kms:Decrypt") and .Resource=="*")' > /dev/null; then
            unrestricted_found=true
            need_fix+=("IAM Role|$role_name|Unrestricted KMS decrypt")
            log "WARNING" "Role $role_name has unrestricted KMS decryption in policy $policy. Fixing..."
            
            # Create a new policy with restricted access
            local new_policy
            new_policy=$(echo "$policy_doc" | jq '
                .Statement = [.Statement[] | 
                    if (.Effect=="Allow" and (.Action=="kms:Decrypt" or .Action[]=="kms:Decrypt") and .Resource=="*") then
                        .Resource = ["arn:aws:kms:'$REGION':'$ACCOUNT_ID':key/*"]
                    else
                        .
                    end
                ]
            ')
            
            # Apply the updated inline policy
            echo "$new_policy" > temp_inline_policy.json
            aws iam put-role-policy --role-name "$role_name" --policy-name "$policy" --policy-document file://temp_inline_policy.json
            
            if [ $? -eq 0 ]; then
                log "SUCCESS" "Updated inline policy $policy for role $role_name to restrict KMS decryption"
                compliant+=("IAM Role|$role_name|Policy $policy restricted")
            else
                log "ERROR" "Failed to update inline policy $policy for role $role_name"
            fi
            rm temp_inline_policy.json
        fi
    done
    
    if ! $unrestricted_found; then
        compliant+=("IAM Role|$role_name|KMS decrypt restricted")
        log "SUCCESS" "Role $role_name does not have unrestricted KMS decryption in inline policies"
    fi
}

# Function to ensure KMS keys are not pending deletion
ensure_kms_not_pending_deletion() {
    local key_id=$1
    log "INFO" "Checking if KMS key $key_id is pending deletion..."
    
    if ! validate_resource "$key_id" "key"; then
        not_found+=("KMS Key|$key_id")
        log "ERROR" "KMS key $key_id not found"
        return 1
    fi
    
    # Check key status
    local key_state
    key_state=$(aws kms describe-key --key-id "$key_id" --query "KeyMetadata.KeyState" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to check key state for $key_id"
        return 1
    fi
    
    if [[ "$key_state" == "PendingDeletion" ]]; then
        need_fix+=("KMS Key|$key_id|Pending deletion")
        log "WARNING" "KMS key $key_id is pending deletion. Cancelling deletion..."
        
        # Cancel key deletion
        aws kms cancel-key-deletion --key-id "$key_id"
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Cancelled deletion for KMS key $key_id"
            
            # Re-enable the key
            aws kms enable-key --key-id "$key_id"
            
            if [ $? -eq 0 ]; then
                log "SUCCESS" "Re-enabled KMS key $key_id"
                compliant+=("KMS Key|$key_id|Active")
            else
                log "ERROR" "Failed to re-enable KMS key $key_id"
            fi
        else
            log "ERROR" "Failed to cancel deletion for KMS key $key_id"
        fi
    else
        compliant+=("KMS Key|$key_id|Not pending deletion")
        log "SUCCESS" "KMS key $key_id is not pending deletion"
    fi
}

# Function to ensure KMS key decryption is restricted in IAM customer managed policies
ensure_kms_restricted_managed_policy() {
    local policy_arn=$1
    log "INFO" "Checking if IAM policy $policy_arn has unrestricted KMS decryption..."
    
    if ! validate_resource "$policy_arn" "policy"; then
        not_found+=("IAM Policy|$policy_arn")
        log "ERROR" "IAM policy $policy_arn not found"
        return 1
    fi
    
    # Get the policy version ID
    local version_id
    version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query "Policy.DefaultVersionId" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to get policy version for $policy_arn"
        return 1
    fi
    
    # Get the policy document
    local policy_doc
    policy_doc=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query "PolicyVersion.Document" --output json)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to get policy document for $policy_arn"
        return 1
    fi
    
    # Check for unrestricted KMS decrypt permissions
    if echo "$policy_doc" | jq -e '.Statement[] | select(.Effect=="Allow" and (.Action=="kms:Decrypt" or .Action[]=="kms:Decrypt") and .Resource=="*")' > /dev/null; then
        need_fix+=("IAM Policy|$policy_arn|Unrestricted KMS decrypt")
        log "WARNING" "Policy $policy_arn has unrestricted KMS decryption. Creating a new version..."
        
        # Create a new policy with restricted access
        local new_policy
        new_policy=$(echo "$policy_doc" | jq '
            .Statement = [.Statement[] | 
                if (.Effect=="Allow" and (.Action=="kms:Decrypt" or .Action[]=="kms:Decrypt") and .Resource=="*") then
                    .Resource = ["arn:aws:kms:'$REGION':'$ACCOUNT_ID':key/*"]
                else
                    .
                end
            ]
        ')
        
        # Create a new policy version
        echo "$new_policy" > temp_managed_policy.json
        
        # Check if we need to clean up old versions (max 5 versions allowed)
        local non_default_versions
        non_default_versions=$(aws iam list-policy-versions --policy-arn "$policy_arn" --query "Versions[?!IsDefaultVersion].VersionId" --output text)
        
        if [ $(echo "$non_default_versions" | wc -w) -ge 4 ]; then
            # Delete the oldest non-default version
            oldest_version=$(echo "$non_default_versions" | tr ' ' '\n' | head -n 1)
            log "INFO" "Deleting oldest policy version $oldest_version to make room for new version"
            aws iam delete-policy-version --policy-arn "$policy_arn" --version-id "$oldest_version"
        fi
        
        # Create new policy version
        aws iam create-policy-version --policy-arn "$policy_arn" --policy-document file://temp_managed_policy.json --set-as-default
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Created new version of policy $policy_arn with restricted KMS decryption"
            compliant+=("IAM Policy|$policy_arn|KMS decrypt restricted")
        else
            log "ERROR" "Failed to create new version of policy $policy_arn"
        fi
        rm temp_managed_policy.json
    else
        compliant+=("IAM Policy|$policy_arn|KMS decrypt restricted")
        log "SUCCESS" "Policy $policy_arn does not have unrestricted KMS decryption"
    fi
}

# Function to remediate all KMS controls for a single key
remediate_all_kms_controls() {
    local key_id=$1
    log "INFO" "Running all KMS controls on key $key_id..."
    
    # Run all KMS key checks
    ensure_kms_rotation "$key_id"
    ensure_kms_in_use "$key_id"
    ensure_kms_no_public_access "$key_id"
    ensure_kms_not_pending_deletion "$key_id"
    
    log "SUCCESS" "Completed all KMS controls for key $key_id"
}

# Function to scan and remediate all KMS keys
scan_all_kms_keys() {
    log "INFO" "Scanning all KMS keys in account $ACCOUNT_ID..."
    
    # Ensure EBS encryption by default is enabled (account-level check)
    ensure_ebs_encryption_default
    
    # Get all KMS customer managed keys
    local keys
    keys=$(aws kms list-keys --query "Keys[].KeyId" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to list KMS keys"
        return 1
    fi
    
    if [[ -z "$keys" ]]; then
        log "INFO" "No KMS keys found in account"
        return 0
    fi
    
    local key_count=0
    for key_id in $keys; do
        remediate_all_kms_controls "$key_id"
        ((key_count++))
    done
    
    log "SUCCESS" "Scanned and remediated $key_count KMS keys"
    
    # Now scan IAM roles for unrestricted KMS policies
    log "INFO" "Scanning IAM roles for unrestricted KMS decryption..."
    
    local roles
    roles=$(aws iam list-roles --query "Roles[].RoleName" --output text)
    
    for role in $roles; do
        ensure_kms_restricted_inline_policy "$role"
    done
    
    # Check customer managed policies
    log "INFO" "Scanning customer managed policies for unrestricted KMS decryption..."
    
    local managed_policies
    managed_policies=$(aws iam list-policies --scope Local --query "Policies[].Arn" --output text)
    
    for policy_arn in $managed_policies; do
        ensure_kms_restricted_managed_policy "$policy_arn"
    done
}

# Function to process CSV input
process_csv() {
    local csv_file=$1
    shift
    local selected_controls=("$@")
    
    log "INFO" "Processing CSV file: $csv_file"
    log "INFO" "Selected controls: ${selected_controls[*]}"
    
    while IFS=, read -r _ _ _ _ control _ _ _ resource _; do
        # Skip header and empty lines
        [[ "$control" == "Control" || -z "$control" ]] && continue
        
        # Check if control is in selected controls
        local control_selected=false
        for selected in "${selected_controls[@]}"; do
            if [[ "$control" == "$selected" ]]; then
                control_selected=true
                break
            fi
        done
        
        if ! $control_selected; then
            continue
        fi
        
        log "INFO" "Processing control: $control"
        
        # Get function name from mappings
        local function_name
        function_name=$(yq eval ".controls.[\"$control\"].function" kms_control_mappings.yaml)
        
        if [[ -z "$function_name" ]]; then
            log "WARNING" "No function mapping found for control: $control"
            continue
        fi
        
        # Extract resource ID (key-id, role name, policy ARN)
        local resource_id
        
        # Different regex patterns based on resource type
        if [[ "$control" == *"IAM inline policy"* ]]; then
            # For IAM roles
            resource_id=$(echo "$resource" | grep -oE '[a-zA-Z0-9_+=,.@-]+Role')
        elif [[ "$control" == *"IAM customer managed policy"* ]]; then
            # For IAM policies
            resource_id=$(echo "$resource" | grep -oE 'arn:aws:iam::[0-9]+:policy/[a-zA-Z0-9_+=,.@-]+')
        else
            # For KMS keys
            resource_id=$(echo "$resource" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
        fi
        
        if [[ -n "$resource_id" ]]; then
            log "INFO" "Executing $function_name on $resource_id"
            $function_name "$resource_id"
        else
            log "WARNING" "Could not extract resource ID from: $resource"
        fi
    done < "$csv_file"
}

# Function to ensure EBS encryption by default is enabled
ensure_ebs_encryption_default() {
    log "INFO" "Checking EBS encryption by default..."
    local status
    status=$(aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to check EBS encryption by default"
        return 1
    fi

    if [[ "$status" == "false" ]]; then
        need_fix+=("Account|$ACCOUNT_ID|EBS encryption by default disabled")
        log "WARNING" "EBS encryption by default is not enabled. Enabling now..."

        # Enable EBS encryption by default
        aws ec2 enable-ebs-encryption-by-default

        if [ $? -eq 0 ]; then
            compliant+=("Account|$ACCOUNT_ID|EBS encryption by default enabled")
            log "SUCCESS" "EBS encryption by default has been enabled for account $ACCOUNT_ID."
        else
            log "ERROR" "Failed to enable EBS encryption by default."
        fi
    else
        compliant+=("Account|$ACCOUNT_ID|EBS encryption by default enabled")
        log "SUCCESS" "EBS encryption by default is already enabled."
    fi
}

# Print script header
print_header() {
    echo -e "\n${BLUE}=================================================${NC}"
    echo -e "${BLUE}    KMS Security Compliance Automation Script     ${NC}"
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${BLUE}This script will check and remediate KMS security controls.${NC}"
    echo -e "${BLUE}=================================================${NC}\n"
}

# Main function
main() {
    print_header
    check_aws_configuration
    
    if [[ $# -eq 0 ]]; then
        log "INFO" "No arguments provided. Scanning all KMS keys..."
        scan_all_kms_keys
    elif [[ $# -eq 1 && "$1" == "--help" ]]; then
        echo "Usage:"
        echo "  $0                          # Scan and remediate all KMS keys"
        echo "  $0 <csv_file> <control>     # Process specific control from CSV file"
        echo "  $0 <key_id>                 # Remediate specific KMS key"
        echo "  $0 --help                   # Show this help message"
        exit 0
    elif [[ $# -eq 1 && "$1" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]]; then
        log "INFO" "Remediating single KMS key: $1"
        remediate_all_kms_controls "$1"
    elif [[ $# -ge 2 && -f "$1" ]]; then
        log "INFO" "Processing CSV file with selected controls"
        process_csv "$@"
    else
        log "ERROR" "Invalid arguments. Use --help for usage information."
        exit 1
    fi
    
    # Print summary
    log "INFO" "Final Summary: ${#need_fix[@]} need fixes, ${#compliant[@]} compliant, ${#not_found[@]} not found."
    
    if [[ ${#need_fix[@]} -gt 0 ]]; then
        log "WARNING" "Resources that needed fixes:"
        for item in "${need_fix[@]}"; do
            IFS='|' read -r type id issue <<< "$item"
            log "WARNING" "$type: $id - $issue"
        done
    fi
    
    if [[ ${#not_found[@]} -gt 0 ]]; then
        log "ERROR" "Resources not found:"
        for item in "${not_found[@]}"; do
            IFS='|' read -r type id <<< "$item"
            log "ERROR" "$type: $id"
        done
    fi
    
    log "SUCCESS" "KMS security compliance check completed."
}

main "$@"
