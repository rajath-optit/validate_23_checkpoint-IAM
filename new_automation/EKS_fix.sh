#!/bin/bash

# Configuration file for EKS control mappings
cat > eks_control_mappings.yaml << 'EOF'
controls:
  "EKS clusters endpoint should restrict public access":
    function: "restrict_public_access"
    description: "Ensures EKS clusters restrict public access to their endpoints"
  "EKS clusters should have control plane audit logging enabled":
    function: "enable_audit_logging"
    description: "Ensures EKS clusters have control plane audit logging enabled"
  "EKS clusters should be configured to have kubernetes secrets encrypted using KMS":
    function: "enable_kms_encryption"
    description: "Ensures EKS clusters have Kubernetes secrets encrypted using KMS"
  "EKS clusters should not be configured within a default VPC":
    function: "enforce_non_default_vpc"
    description: "Ensures EKS clusters are not configured within a default VPC"
  "EKS clusters should not use multiple security groups":
    function: "enforce_single_security_group"
    description: "Ensures EKS clusters do not use multiple security groups"
  "EKS clusters endpoint public access should be restricted":
    function: "restrict_public_access"
    description: "Ensures EKS clusters restrict public access to their endpoints"
  "EKS clusters should run on a supported Kubernetes version":
    function: "enforce_supported_k8s_version"
    description: "Ensures EKS clusters run on a supported Kubernetes version"
EOF

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Arrays to store resources
declare -a need_fix=()
declare -a compliant=()
declare -a not_found=()

# Function to log messages with timestamp
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

# Function to validate AWS EKS resources
validate_cluster() {
    local cluster_name=$1
    aws eks describe-cluster --name "$cluster_name" &>/dev/null && return 0
    return 1
}

# Function to restrict public access for EKS clusters
restrict_public_access() {
    local cluster_name=$1
    log "INFO" "Checking if cluster $cluster_name has public access enabled..."
    
    if ! validate_cluster "$cluster_name"; then
        not_found+=("Cluster|$cluster_name")
        log "ERROR" "Cluster $cluster_name not found"
        return 1
    fi
    
    local public_access
    public_access=$(aws eks describe-cluster --name "$cluster_name" --query "cluster.resourcesVpcConfig.endpointPublicAccess" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to check public access settings for cluster $cluster_name"
        return 1
    fi

    if [[ "$public_access" == "True" ]]; then
        need_fix+=("Cluster|$cluster_name|Public access enabled")
        log "WARNING" "Cluster $cluster_name has public access enabled. Restricting now..."

        # Update the cluster to disable public access
        aws eks update-cluster-config \
            --name "$cluster_name" \
            --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Public access disabled for EKS cluster: $cluster_name"
            compliant+=("Cluster|$cluster_name|Public access restricted")
        else
            log "ERROR" "Failed to disable public access for cluster $cluster_name"
        fi
    else
        compliant+=("Cluster|$cluster_name|Public access restricted")
        log "SUCCESS" "Cluster $cluster_name already has public access restricted"
    fi
}

# Function to enable control plane audit logging
enable_audit_logging() {
    local cluster_name=$1
    log "INFO" "Checking control plane audit logging for cluster $cluster_name..."
    
    if ! validate_cluster "$cluster_name"; then
        not_found+=("Cluster|$cluster_name")
        log "ERROR" "Cluster $cluster_name not found"
        return 1
    fi
    
    local logging_status
    logging_status=$(aws eks describe-cluster --name "$cluster_name" --query "cluster.logging.clusterLogging[?logTypes=='audit'].enabled" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to check control plane logging for cluster $cluster_name"
        return 1
    fi

    if [[ "$logging_status" != "True" ]]; then
        need_fix+=("Cluster|$cluster_name|Audit logging disabled")
        log "WARNING" "Control plane audit logging is NOT enabled for cluster $cluster_name. Enabling now..."

        # Enable control plane logging for audit logs
        aws eks update-cluster-config \
            --name "$cluster_name" \
            --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Control plane audit logging enabled for EKS cluster: $cluster_name"
            compliant+=("Cluster|$cluster_name|Audit logging enabled")
        else
            log "ERROR" "Failed to enable control plane audit logging for cluster $cluster_name"
        fi
    else
        compliant+=("Cluster|$cluster_name|Audit logging enabled")
        log "SUCCESS" "Cluster $cluster_name already has control plane audit logging enabled"
    fi
}

# Function to enable KMS encryption for Kubernetes secrets
enable_kms_encryption() {
    local cluster_name=$1
    log "INFO" "Checking KMS encryption for Kubernetes secrets in cluster $cluster_name..."
    
    if ! validate_cluster "$cluster_name"; then
        not_found+=("Cluster|$cluster_name")
        log "ERROR" "Cluster $cluster_name not found"
        return 1
    fi
    
    local encryption_status
    encryption_status=$(aws eks describe-cluster --name "$cluster_name" --query "cluster.encryptionConfig[?resources[0]=='secrets'].provider.keyArn" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to check encryption configuration for cluster $cluster_name"
        return 1
    fi

    if [[ -z "$encryption_status" ]]; then
        need_fix+=("Cluster|$cluster_name|KMS encryption disabled")
        log "WARNING" "Kubernetes secrets in cluster $cluster_name are NOT encrypted with KMS. Enabling now..."

        # Create a KMS key if one doesn't exist specifically for EKS
        local kms_key_id
        kms_key_id=$(aws kms list-aliases --query "Aliases[?starts_with(AliasName, 'alias/eks-')].TargetKeyId" --output text)
        
        if [[ -z "$kms_key_id" ]]; then
            log "INFO" "Creating new KMS key for EKS encryption..."
            kms_key_id=$(aws kms create-key --description "Key for EKS Secrets Encryption" --query KeyMetadata.KeyId --output text)
            aws kms create-alias --alias-name "alias/eks-secrets-encryption" --target-key-id "$kms_key_id"
            log "INFO" "Created new KMS key with ID: $kms_key_id"
        else
            log "INFO" "Using existing KMS key with ID: $kms_key_id"
        fi

        # Enable KMS encryption for Kubernetes secrets
        aws eks associate-encryption-config \
            --cluster-name "$cluster_name" \
            --encryption-config '[{"resources":["secrets"],"provider":{"keyArn":"'"$(aws kms describe-key --key-id "$kms_key_id" --query KeyMetadata.Arn --output text)"'"}}]'
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "KMS encryption enabled for Kubernetes secrets in cluster: $cluster_name"
            compliant+=("Cluster|$cluster_name|KMS encryption enabled")
        else
            log "ERROR" "Failed to enable KMS encryption for Kubernetes secrets in cluster $cluster_name"
        fi
    else
        compliant+=("Cluster|$cluster_name|KMS encryption enabled")
        log "SUCCESS" "Cluster $cluster_name already has KMS encryption for Kubernetes secrets"
    fi
}

# Function to enforce non-default VPC for EKS
enforce_non_default_vpc() {
    local cluster_name=$1
    log "INFO" "Checking if cluster $cluster_name is in a default VPC..."
    
    if ! validate_cluster "$cluster_name"; then
        not_found+=("Cluster|$cluster_name")
        log "ERROR" "Cluster $cluster_name not found"
        return 1
    fi
    
    local vpc_id
    vpc_id=$(aws eks describe-cluster --name "$cluster_name" --query "cluster.resourcesVpcConfig.vpcId" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to get VPC ID for cluster $cluster_name"
        return 1
    fi

    # Get the default VPC ID in the region
    local default_vpc_id
    default_vpc_id=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text)
    
    if [[ "$vpc_id" == "$default_vpc_id" ]]; then
        need_fix+=("Cluster|$cluster_name|In default VPC")
        log "WARNING" "Cluster $cluster_name is in the default VPC $default_vpc_id. Migration needed."
        
        # Find or create a non-default VPC
        local custom_vpc_id
        custom_vpc_id=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=false" --query "Vpcs[0].VpcId" --output text)
        
        if [[ -z "$custom_vpc_id" || "$custom_vpc_id" == "None" ]]; then
            log "INFO" "No custom VPC found. Creating new VPC..."
            # Create a new VPC (simplified example)
            custom_vpc_id=$(aws ec2 create-vpc --cidr-block 10.0.0.0/16 --query Vpc.VpcId --output text)
            aws ec2 create-tags --resources "$custom_vpc_id" --tags Key=Name,Value=EKS-Custom-VPC
            
            # Create subnets (minimum 2 in different AZs for EKS)
            local az1 az2
            az1=$(aws ec2 describe-availability-zones --query "AvailabilityZones[0].ZoneName" --output text)
            az2=$(aws ec2 describe-availability-zones --query "AvailabilityZones[1].ZoneName" --output text)
            
            subnet1_id=$(aws ec2 create-subnet --vpc-id "$custom_vpc_id" --cidr-block 10.0.1.0/24 --availability-zone "$az1" --query Subnet.SubnetId --output text)
            subnet2_id=$(aws ec2 create-subnet --vpc-id "$custom_vpc_id" --cidr-block 10.0.2.0/24 --availability-zone "$az2" --query Subnet.SubnetId --output text)
            
            log "INFO" "Created new VPC $custom_vpc_id with subnets $subnet1_id and $subnet2_id"
        else
            log "INFO" "Found existing custom VPC: $custom_vpc_id"
            # Get existing subnets
            subnet1_id=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$custom_vpc_id" --query "Subnets[0].SubnetId" --output text)
            subnet2_id=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$custom_vpc_id" --query "Subnets[1].SubnetId" --output text)
        fi
        
        log "WARNING" "EKS clusters in default VPC require recreation. Cannot be migrated in-place."
        log "INFO" "Steps to recreate cluster in custom VPC:"
        log "INFO" "1. Create new EKS cluster in custom VPC $custom_vpc_id"
        log "INFO" "2. Migrate workloads to the new cluster"
        log "INFO" "3. Delete the old cluster in default VPC"
        
        # We can't automatically migrate an EKS cluster to a new VPC, so we provide guidance
        log "INFO" "Command to create new cluster in custom VPC:"
        echo "aws eks create-cluster --name $cluster_name-new --role-arn \$(aws eks describe-cluster --name $cluster_name --query cluster.roleArn --output text) --resources-vpc-config subnetIds=$subnet1_id,$subnet2_id,securityGroupIds=\$(aws eks describe-cluster --name $cluster_name --query cluster.resourcesVpcConfig.securityGroupIds[0] --output text) --kubernetes-version \$(aws eks describe-cluster --name $cluster_name --query cluster.version --output text)"
    else
        compliant+=("Cluster|$cluster_name|Not in default VPC")
        log "SUCCESS" "Cluster $cluster_name is not in the default VPC"
    fi
}

# Function to enforce single security group for EKS
enforce_single_security_group() {
    local cluster_name=$1
    log "INFO" "Checking security group configuration for cluster $cluster_name..."
    
    if ! validate_cluster "$cluster_name"; then
        not_found+=("Cluster|$cluster_name")
        log "ERROR" "Cluster $cluster_name not found"
        return 1
    fi
    
    local sg_ids
    sg_ids=$(aws eks describe-cluster --name "$cluster_name" --query "cluster.resourcesVpcConfig.securityGroupIds" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to get security groups for cluster $cluster_name"
        return 1
    fi

    # Count the number of security groups
    local sg_count
    sg_count=$(echo "$sg_ids" | wc -w)
    
    if [[ $sg_count -gt 1 ]]; then
        need_fix+=("Cluster|$cluster_name|Multiple security groups")
        log "WARNING" "Cluster $cluster_name is using multiple security groups. Restricting to one now..."

        # Get the first security group ID
        local primary_sg
        primary_sg=$(echo "$sg_ids" | awk '{print $1}')
        
        # Update the cluster to use only one security group
        aws eks update-cluster-config \
            --name "$cluster_name" \
            --resources-vpc-config securityGroupIds="$primary_sg"
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Updated cluster $cluster_name to use a single security group: $primary_sg"
            compliant+=("Cluster|$cluster_name|Single security group")
        else
            log "ERROR" "Failed to update security group configuration for cluster $cluster_name"
        fi
    else
        compliant+=("Cluster|$cluster_name|Single security group")
        log "SUCCESS" "Cluster $cluster_name is already using a single security group"
    fi
}

# Function to enforce supported Kubernetes version
enforce_supported_k8s_version() {
    local cluster_name=$1
    log "INFO" "Checking Kubernetes version for cluster $cluster_name..."
    
    if ! validate_cluster "$cluster_name"; then
        not_found+=("Cluster|$cluster_name")
        log "ERROR" "Cluster $cluster_name not found"
        return 1
    fi
    
    local current_version
    current_version=$(aws eks describe-cluster --name "$cluster_name" --query "cluster.version" --output text)
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to get Kubernetes version for cluster $cluster_name"
        return 1
    fi

    # Get available Kubernetes versions from EKS (dynamically)
    local available_versions
    available_versions=$(aws eks describe-addon-versions --query "addons[0].addonVersions[].compatibilities[].clusterVersion" --output text | sort -u)
    
    # Check if current version is in the list of supported versions
    if ! echo "$available_versions" | grep -q "$current_version"; then
        need_fix+=("Cluster|$cluster_name|Unsupported K8s version")
        log "WARNING" "Cluster $cluster_name is running an unsupported Kubernetes version ($current_version)"
        
        # Get the latest supported version
        local latest_version
        latest_version=$(echo "$available_versions" | sort -V | tail -n 1)
        
        log "INFO" "Latest supported version is $latest_version. Upgrading cluster $cluster_name..."
        
        # Upgrade to the latest supported version
        aws eks update-cluster-version \
            --name "$cluster_name" \
            --kubernetes-version "$latest_version"
        
        if [ $? -eq 0 ]; then
            log "SUCCESS" "Upgrading cluster $cluster_name to Kubernetes version $latest_version"
            log "INFO" "Upgrade process started. This may take several minutes to complete."
            compliant+=("Cluster|$cluster_name|Supported K8s version")
        else
            log "ERROR" "Failed to upgrade Kubernetes version for cluster $cluster_name"
        fi
    else
        compliant+=("Cluster|$cluster_name|Supported K8s version")
        log "SUCCESS" "Cluster $cluster_name is running a supported Kubernetes version ($current_version)"
    fi
}

# Function to process all clusters or a specific cluster
process_clusters() {
    local specified_cluster=$1
    shift
    local selected_controls=("$@")
    
    log "INFO" "Getting EKS clusters..."
    
    local clusters
    if [[ -n "$specified_cluster" ]]; then
        clusters=("$specified_cluster")
    else
        clusters=($(aws eks list-clusters --query "clusters[]" --output text))
    fi
    
    if [[ ${#clusters[@]} -eq 0 ]]; then
        log "WARNING" "No EKS clusters found."
        return 0
    fi
    
    log "INFO" "Found ${#clusters[@]} EKS clusters. Processing..."
    
    for cluster_name in "${clusters[@]}"; do
        log "INFO" "Processing cluster: $cluster_name"
        
        for control in "${selected_controls[@]}"; do
            log "INFO" "Applying control: $control"
            function_name=$(yq eval ".controls.[\"$control\"].function" eks_control_mappings.yaml)
            
            if [[ -z "$function_name" ]]; then
                log "WARNING" "No function defined for control: $control"
                continue
            fi
            
            $function_name "$cluster_name"
        done
    done
}

# Function to process CSV input
process_csv() {
    local csv_file=$1
    shift
    local selected_controls=("$@")
    
    log "INFO" "Processing CSV file: $csv_file"
    
    while IFS=, read -r _ _ _ _ control _ _ _ resource _; do
        [[ " ${selected_controls[@]} " =~ " ${control} " ]] || continue
        
        log "INFO" "Processing control: $control"
        function_name=$(yq eval ".controls.[\"$control\"].function" eks_control_mappings.yaml)
        
        [[ -z "$function_name" ]] && continue
        
        # Extract cluster name from resource field
        cluster_name=$(echo "$resource" | grep -o 'eks.*' | cut -d'/' -f2)
        
        [[ -n "$cluster_name" ]] && $function_name "$cluster_name"
    done < <(tail -n +2 "$csv_file")
}

# Function to display available controls
list_controls() {
    echo "Available EKS controls:"
    yq eval '.controls | keys' eks_control_mappings.yaml | sed 's/- /  /'
}

# Function to display help
show_help() {
    echo "Usage: $0 [options] [control1] [control2] ..."
    echo "Options:"
    echo "  --csv <file>       Process controls from CSV file"
    echo "  --cluster <name>   Specify a single cluster to process"
    echo "  --all-clusters     Process all clusters (default)"
    echo "  --list-controls    List available controls"
    echo "  --help             Show this help message"
    echo ""
    echo "If no control is specified, all controls will be applied."
    echo ""
    echo "Example:"
    echo "  $0 --cluster my-cluster \"EKS clusters endpoint should restrict public access\""
    echo "  $0 --csv findings.csv \"EKS clusters should have control plane audit logging enabled\""
    echo "  $0 --all-clusters"
}

# Main function
main() {
    check_aws_configuration
    
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi
    
    local csv_file=""
    local specified_cluster=""
    local all_clusters=false
    local controls=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --csv)
                csv_file="$2"
                shift 2
                ;;
            --cluster)
                specified_cluster="$2"
                shift 2
                ;;
            --all-clusters)
                all_clusters=true
                shift
                ;;
            --list-controls)
                list_controls
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                controls+=("$1")
                shift
                ;;
        esac
    done
    
    # If no controls specified, use all controls
    if [[ ${#controls[@]} -eq 0 ]]; then
        readarray -t controls < <(yq eval '.controls | keys' eks_control_mappings.yaml | sed 's/- //')
    fi
    
    log "INFO" "Selected controls: ${controls[*]}"
    
    if [[ -n "$csv_file" ]]; then
        process_csv "$csv_file" "${controls[@]}"
    elif [[ -n "$specified_cluster" ]]; then
        process_clusters "$specified_cluster" "${controls[@]}"
    else
        process_clusters "" "${controls[@]}"
    fi
    
    # Print summary
    log "INFO" "Summary:"
    log "INFO" "  Compliant: ${#compliant[@]}"
    log "INFO" "  Need Fix: ${#need_fix[@]}"
    log "INFO" "  Not Found: ${#not_found[@]}"
    
    # Print details if any resources need fixing
    if [[ ${#need_fix[@]} -gt 0 ]]; then
        log "WARNING" "Resources that need fixing:"
        for resource in "${need_fix[@]}"; do
            IFS='|' read -r type id issue <<< "$resource"
            log "WARNING" "  $type: $id - $issue"
        done
    fi
    
    # Print details of compliant resources
    if [[ ${#compliant[@]} -gt 0 ]]; then
        log "SUCCESS" "Compliant resources:"
        for resource in "${compliant[@]}"; do
            IFS='|' read -r type id status <<< "$resource"
            log "SUCCESS" "  $type: $id - $status"
        done
    fi
}

# Check if the script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
