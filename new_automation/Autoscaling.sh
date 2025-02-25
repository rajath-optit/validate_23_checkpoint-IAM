#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to check and disable public IP in Auto Scaling Launch Configurations
check_public_ip_in_launch_config() {
    log "INFO" "Checking Auto Scaling Launch Configurations for public IP settings..."

    # Get list of all launch configurations
    configs=$(aws autoscaling describe-launch-configurations --query "LaunchConfigurations[].LaunchConfigurationName" --output text)

    if [[ -z "$configs" ]]; then
        log "INFO" "No Launch Configurations found."
        return 0
    fi

    for config in $configs; do
        log "INFO" "Checking Launch Configuration: $config"

        # Get the AssociatePublicIpAddress value
        public_ip=$(aws autoscaling describe-launch-configurations --launch-configuration-names "$config" \
            --query "LaunchConfigurations[0].AssociatePublicIpAddress" --output text 2>/dev/null)

        if [[ "$public_ip" == "True" ]]; then
            log "WARNING" "Launch Configuration $config has public IP enabled!"
            log "INFO" "AWS recommends using Launch Templates instead of Launch Configurations."
            
            # Get associated ASG
            asg=$(aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[?LaunchConfigurationName=='$config'].AutoScalingGroupName" --output text)
            
            if [[ -n "$asg" ]]; then
                log "INFO" "Creating new Launch Template to replace Launch Configuration $config..."
                
                # Get current LC details
                lc_details=$(aws autoscaling describe-launch-configurations --launch-configuration-names "$config" --output json)
                
                # Create new Launch Template with public IP disabled
                lt_name="${config}-template"
                lt_id=$(aws ec2 create-launch-template --launch-template-name "$lt_name" \
                    --version-description "Created from LC $config with public IP disabled" \
                    --launch-template-data "{
                        \"ImageId\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].ImageId'),
                        \"InstanceType\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].InstanceType'),
                        \"SecurityGroupIds\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].SecurityGroups'),
                        \"NetworkInterfaces\": [{
                            \"DeviceIndex\": 0,
                            \"AssociatePublicIpAddress\": false
                        }],
                        \"MetadataOptions\": {
                            \"HttpTokens\": \"required\",
                            \"HttpPutResponseHopLimit\": 1
                        }
                    }" \
                    --query "LaunchTemplate.LaunchTemplateId" --output text)
                
                if [[ -n "$lt_id" ]]; then
                    log "SUCCESS" "Created Launch Template $lt_id ($lt_name)"
                    
                    # Update ASG to use new Launch Template
                    aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
                        --launch-template LaunchTemplateId="$lt_id",Version='$Latest'
                    
                    if [ $? -eq 0 ]; then
                        log "SUCCESS" "Updated ASG $asg to use Launch Template $lt_name with public IP disabled"
                    else
                        log "ERROR" "Failed to update ASG $asg"
                    fi
                else
                    log "ERROR" "Failed to create Launch Template from Launch Configuration $config"
                fi
            else
                log "INFO" "No Auto Scaling Group associated with Launch Configuration $config"
            fi
        else
            log "SUCCESS" "Launch Configuration $config is compliant (no public IP)"
        fi
    done
}

# Function to check and enable tag propagation for Auto Scaling Groups
check_asg_tag_propagation() {
    log "INFO" "Checking Auto Scaling Groups for tag propagation settings..."

    # Get list of all Auto Scaling Groups
    asgs=$(aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[].AutoScalingGroupName" --output text)

    if [[ -z "$asgs" ]]; then
        log "INFO" "No Auto Scaling Groups found."
        return 0
    fi

    for asg in $asgs; do
        log "INFO" "Checking ASG: $asg"

        # Get ASG tags
        tags=$(aws autoscaling describe-tags --filters "Name=auto-scaling-group,Values=$asg" --query "Tags[?PropagateAtLaunch==\`false\`]" --output text)

        if [[ -n "$tags" ]]; then
            log "WARNING" "ASG $asg does NOT propagate some tags to instances!"
            log "INFO" "Enabling tag propagation for $asg..."

            # Get the list of tags
            tag_list=$(aws autoscaling describe-tags --filters "Name=auto-scaling-group,Values=$asg" --query "Tags" --output json)

            # Enable tag propagation for all tags
            for tag in $(echo "$tag_list" | jq -c '.[]'); do
                key=$(echo "$tag" | jq -r '.Key')
                value=$(echo "$tag" | jq -r '.Value')

                aws autoscaling create-or-update-tags --tags "ResourceId=$asg,ResourceType=auto-scaling-group,Key=$key,Value=$value,PropagateAtLaunch=true"
                
                if [ $? -eq 0 ]; then
                    log "SUCCESS" "Tag propagation enabled for tag $key on ASG $asg"
                else
                    log "ERROR" "Failed to enable tag propagation for tag $key on ASG $asg"
                fi
            done

            log "SUCCESS" "Tag propagation enabled for all tags on ASG $asg"
        else
            log "SUCCESS" "ASG $asg is already propagating all tags"
        fi
    done
}

# Function to check Auto Scaling groups for launch template usage
check_asg_launch_templates() {
    log "INFO" "Checking Auto Scaling Groups for use of launch templates..."

    asgs=$(aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[].AutoScalingGroupName" --output text)
    if [[ -z "$asgs" ]]; then
        log "INFO" "No Auto Scaling Groups found."
        return 0
    fi

    for asg in $asgs; do
        launch_template=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" --query "AutoScalingGroups[0].LaunchTemplate" --output text 2>/dev/null)
        launch_config=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" --query "AutoScalingGroups[0].LaunchConfigurationName" --output text 2>/dev/null)

        if [[ -n "$launch_template" && "$launch_template" != "None" ]]; then
            log "SUCCESS" "Auto Scaling Group $asg is using a launch template"
        elif [[ -n "$launch_config" && "$launch_config" != "None" ]]; then
            log "WARNING" "Auto Scaling Group $asg is using a launch configuration. Migration recommended!"
            log "INFO" "Migrating $asg to use a launch template..."
            
            # Get the launch configuration details
            lc_details=$(aws autoscaling describe-launch-configurations --launch-configuration-names "$launch_config" --output json)
            
            # Create a new launch template
            lt_name="${launch_config}-template"
            lt_id=$(aws ec2 create-launch-template --launch-template-name "$lt_name" \
                --version-description "Created from Launch Configuration $launch_config" \
                --launch-template-data "{
                    \"ImageId\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].ImageId'),
                    \"InstanceType\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].InstanceType'),
                    \"SecurityGroupIds\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].SecurityGroups'),
                    \"MetadataOptions\": {
                        \"HttpTokens\": \"required\",
                        \"HttpPutResponseHopLimit\": 1
                    }
                }" \
                --query "LaunchTemplate.LaunchTemplateId" --output text)
            
            if [[ -n "$lt_id" ]]; then
                # Update the ASG to use the new launch template
                aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
                    --launch-template LaunchTemplateId="$lt_id",Version='$Latest'
                
                if [ $? -eq 0 ]; then
                    log "SUCCESS" "Auto Scaling Group $asg now using launch template $lt_name"
                else
                    log "ERROR" "Failed to update Auto Scaling Group $asg to use launch template"
                fi
            else
                log "ERROR" "Failed to create launch template from launch configuration $launch_config"
            fi
        else
            log "ERROR" "Auto Scaling Group $asg does not have a launch template or configuration. Action required!"
        fi
    done
}

# Function to check Auto Scaling groups for multi-AZ deployment
check_asg_multi_az() {
    log "INFO" "Checking Auto Scaling Groups for multi-AZ deployment..."

    asgs=$(aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[].AutoScalingGroupName" --output text)
    if [[ -z "$asgs" ]]; then
        log "INFO" "No Auto Scaling Groups found."
        return 0
    fi

    for asg in $asgs; do
        az_count=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" --query "length(AutoScalingGroups[0].AvailabilityZones)" --output text)

        if [[ "$az_count" -gt 1 ]]; then
            log "SUCCESS" "Auto Scaling Group $asg is using multiple Availability Zones ($az_count AZs)"
        else
            log "WARNING" "Auto Scaling Group $asg is using only one Availability Zone. Adding more AZs..."
            
            # Get VPC ID
            vpc_id=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
                --query "AutoScalingGroups[0].VPCZoneIdentifier" --output text | cut -d ',' -f1 | 
                xargs aws ec2 describe-subnets --subnet-ids --query "Subnets[0].VpcId" --output text)
            
            if [[ -n "$vpc_id" ]]; then
                # Get available subnets in different AZs
                available_subnets=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
                    --query "Subnets[].SubnetId" --output text)
                
                # Get current subnet
                current_subnet=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
                    --query "AutoScalingGroups[0].VPCZoneIdentifier" --output text)
                
                # Find subnets in different AZs
                new_subnets="$current_subnet"
                count=1
                
                for subnet in $available_subnets; do
                    if [[ "$current_subnet" != *"$subnet"* ]]; then
                        subnet_az=$(aws ec2 describe-subnets --subnet-ids "$subnet" --query "Subnets[0].AvailabilityZone" --output text)
                        
                        # Check if this AZ is different from existing ones
                        if [[ "$(echo $new_subnets | xargs -n1 aws ec2 describe-subnets --subnet-ids | jq -r '.Subnets[].AvailabilityZone')" != *"$subnet_az"* ]]; then
                            new_subnets="${new_subnets},${subnet}"
                            count=$((count + 1))
                            
                            # Stop when we have at least 2 AZs
                            if [[ $count -ge 2 ]]; then
                                break
                            fi
                        fi
                    fi
                done
                
                # Update ASG with multiple subnets
                if [[ "$new_subnets" != "$current_subnet" ]]; then
                    aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
                        --vpc-zone-identifier "$new_subnets"
                    
                    if [ $? -eq 0 ]; then
                        log "SUCCESS" "Updated Auto Scaling Group $asg to use multiple AZs"
                    else
                        log "ERROR" "Failed to update Auto Scaling Group $asg to use multiple AZs"
                    fi
                else
                    log "WARNING" "Could not find suitable subnets in different AZs for Auto Scaling Group $asg"
                fi
            else
                log "ERROR" "Could not determine VPC for Auto Scaling Group $asg"
            fi
        fi
    done
}

# Function to check and enforce IMDSv2 on Auto Scaling Groups
check_imds_v2_on_asg() {
    log "INFO" "Checking Auto Scaling Groups for IMDSv2 compliance..."

    # Get list of all Auto Scaling Groups
    asgs=$(aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[].AutoScalingGroupName" --output text)

    if [[ -z "$asgs" ]]; then
        log "INFO" "No Auto Scaling Groups found."
        return 0
    fi

    for asg in $asgs; do
        log "INFO" "Checking ASG: $asg"

        # Get launch template used by the ASG
        launch_template_id=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
            --query "AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId" --output text 2>/dev/null)

        if [[ -n "$launch_template_id" && "$launch_template_id" != "None" ]]; then
            # Get latest launch template version
            latest_version=$(aws ec2 describe-launch-template-versions --launch-template-id "$launch_template_id" \
                --query "LaunchTemplateVersions[-1].VersionNumber" --output text)

            # Get current IMDS settings
            imds=$(aws ec2 describe-launch-template-versions --launch-template-id "$launch_template_id" \
                --versions "$latest_version" --query "LaunchTemplateVersions[0].LaunchTemplateData.MetadataOptions.HttpTokens" --output text)

            if [[ "$imds" == "required" ]]; then
                log "SUCCESS" "ASG $asg is already enforcing IMDSv2"
            else
                log "WARNING" "ASG $asg is using IMDSv1. Updating to enforce IMDSv2..."
                
                # Create a new launch template version enforcing IMDSv2
                aws ec2 create-launch-template-version --launch-template-id "$launch_template_id" \
                    --source-version "$latest_version" \
                    --launch-template-data '{"MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1}}'

                if [ $? -eq 0 ]; then
                    # Update ASG to use the new version
                    new_version=$(aws ec2 describe-launch-template-versions --launch-template-id "$launch_template_id" \
                        --query "LaunchTemplateVersions[-1].VersionNumber" --output text)
                    
                    aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
                        --launch-template LaunchTemplateId="$launch_template_id",Version="$new_version"
                    
                    if [ $? -eq 0 ]; then
                        log "SUCCESS" "IMDSv2 enforced on ASG $asg"
                    else
                        log "ERROR" "Failed to update ASG $asg to use new launch template version"
                    fi
                else
                    log "ERROR" "Failed to create new launch template version for $launch_template_id"
                fi
            fi
        else
            # Check if ASG uses a launch configuration
            launch_config=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
                --query "AutoScalingGroups[0].LaunchConfigurationName" --output text)
            
            if [[ -n "$launch_config" && "$launch_config" != "None" ]]; then
                log "WARNING" "ASG $asg is using launch configuration which doesn't support IMDSv2 configuration. Migrating to launch template..."

                # Get launch configuration details
                lc_details=$(aws autoscaling describe-launch-configurations --launch-configuration-names "$launch_config" --output json)
                
                # Create a new launch template with IMDSv2 required
                lt_name="${launch_config}-imdsv2-template"
                lt_id=$(aws ec2 create-launch-template --launch-template-name "$lt_name" \
                    --version-description "Created from Launch Configuration $launch_config with IMDSv2 required" \
                    --launch-template-data "{
                        \"ImageId\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].ImageId'),
                        \"InstanceType\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].InstanceType'),
                        \"SecurityGroupIds\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].SecurityGroups'),
                        \"MetadataOptions\": {
                            \"HttpTokens\": \"required\",
                            \"HttpPutResponseHopLimit\": 1
                        }
                    }" \
                    --query "LaunchTemplate.LaunchTemplateId" --output text)
                
                if [[ -n "$lt_id" ]]; then
                    # Update the ASG to use the new launch template
                    aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
                        --launch-template LaunchTemplateId="$lt_id",Version='$Latest'
                    
                    if [ $? -eq 0 ]; then
                        log "SUCCESS" "ASG $asg updated to use launch template with IMDSv2 required"
                    else
                        log "ERROR" "Failed to update ASG $asg to use launch template"
                    fi
                else
                    log "ERROR" "Failed to create launch template from launch configuration $launch_config"
                fi
            else
                log "ERROR" "ASG $asg does not have a launch template or configuration. Skipping IMDSv2 enforcement."
            fi
        fi
    done
}

# Function to check and update Auto Scaling Groups for multi-AZ and multiple instance types
check_asg_multi_az_and_types() {
    log "INFO" "Checking Auto Scaling Groups for multiple instance types and AZs..."

    # Get list of all Auto Scaling Groups
    asgs=$(aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[].AutoScalingGroupName" --output text)

    if [[ -z "$asgs" ]]; then
        log "INFO" "No Auto Scaling Groups found."
        return 0
    fi

    for asg in $asgs; do
        log "INFO" "Checking ASG: $asg"

        # Get instance types used by the ASG
        mixed_instances=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
            --query "AutoScalingGroups[0].MixedInstancesPolicy" --output text)
        
        # Get number of AZs used by the ASG
        az_count=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
            --query "length(AutoScalingGroups[0].AvailabilityZones)" --output text)

        # Check if using mixed instances
        if [[ "$mixed_instances" == "None" ]]; then
            log "WARNING" "ASG $asg is not using mixed instances. Updating..."
            
            # Get current launch template or configuration
            launch_template_id=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
                --query "AutoScalingGroups[0].LaunchTemplate.LaunchTemplateId" --output text)
            
            launch_config=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
                --query "AutoScalingGroups[0].LaunchConfigurationName" --output text)
            
            if [[ -n "$launch_template_id" && "$launch_template_id" != "None" ]]; then
                # Get current instance type
                current_instance=$(aws ec2 describe-launch-template-versions --launch-template-id "$launch_template_id" \
                    --versions '$Latest' --query "LaunchTemplateVersions[0].LaunchTemplateData.InstanceType" --output text)
                
                # Determine alternative instance type
                if [[ "$current_instance" == *"micro"* ]]; then
                    alt_instance="${current_instance/micro/small}"
                elif [[ "$current_instance" == *"small"* ]]; then
                    alt_instance="${current_instance/small/medium}"
                else
                    # If not micro or small, use a smaller instance type
                    instance_family=$(echo "$current_instance" | cut -d'.' -f1)
                    alt_instance="${instance_family}.micro"
                fi
                
                # Update ASG to use mixed instances policy
                aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
                    --mixed-instances-policy "{
                        \"LaunchTemplate\": {
                            \"LaunchTemplateSpecification\": {
                                \"LaunchTemplateId\": \"$launch_template_id\",
                                \"Version\": \"\$Latest\"
                            },
                            \"Overrides\": [
                                {\"InstanceType\": \"$current_instance\"},
                                {\"InstanceType\": \"$alt_instance\"}
                            ]
                        },
                        \"InstancesDistribution\": {
                            \"OnDemandAllocationStrategy\": \"prioritized\",
                            \"OnDemandBaseCapacity\": 1,
                            \"OnDemandPercentageAboveBaseCapacity\": 100,
                            \"SpotAllocationStrategy\": \"capacity-optimized\"
                        }
                    }"
                
                if [ $? -eq 0 ]; then
                    log "SUCCESS" "ASG $asg updated to use multiple instance types"
                else
                    log "ERROR" "Failed to update ASG $asg to use multiple instance types"
                fi
            elif [[ -n "$launch_config" && "$launch_config" != "None" ]]; then
                log "WARNING" "ASG $asg is using launch configuration. Migration to launch template with mixed instances required..."
                
                # Get current details
                lc_details=$(aws autoscaling describe-launch-configurations --launch-configuration-names "$launch_config" --output json)
                current_instance=$(echo $lc_details | jq -r '.LaunchConfigurations[0].InstanceType')
                
                # Determine alternative instance type
                if [[ "$current_instance" == *"micro"* ]]; then
                    alt_instance="${current_instance/micro/small}"
                elif [[ "$current_instance" == *"small"* ]]; then
                    alt_instance="${current_instance/small/medium}"
                else
                    # If not micro or small, use a smaller instance type
                    instance_family=$(echo "$current_instance" | cut -d'.' -f1)
                    alt_instance="${instance_family}.micro"
                fi
                
                # Create new launch template
                lt_name="${launch_config}-mixed-template"
                lt_id=$(aws ec2 create-launch-template --launch-template-name "$lt_name" \
                    --version-description "Created from Launch Configuration $launch_config for mixed instances" \
                    --launch-template-data "{
                        \"ImageId\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].ImageId'),
                        \"SecurityGroupIds\": $(echo $lc_details | jq -r '.LaunchConfigurations[0].SecurityGroups'),
                        \"MetadataOptions\": {
                            \"HttpTokens\": \"required\",
                            \"HttpPutResponseHopLimit\": 1
                        }
                    }" \
                    --query "LaunchTemplate.LaunchTemplateId" --output text)
                
                if [[ -n "$lt_id" ]]; then
                    # Update ASG with mixed instances
                    aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
                        --mixed-instances-policy "{
                            \"LaunchTemplate\": {
                                \"LaunchTemplateSpecification\": {
                                    \"LaunchTemplateId\": \"$lt_id\",
                                    \"Version\": \"\$Latest\"
                                },
                                \"Overrides\": [
                                    {\"InstanceType\": \"$current_instance\"},
                                    {\"InstanceType\": \"$alt_instance\"}
                                ]
                            },
                            \"InstancesDistribution\": {
                                \"OnDemandAllocationStrategy\": \"prioritized\",
                                \"OnDemandBaseCapacity\": 1,
                                \"OnDemandPercentageAboveBaseCapacity\": 100,
                                \"SpotAllocationStrategy\": \"capacity-optimized\"
                            }
                        }"
                    
                    if [ $? -eq 0 ]; then
                        log "SUCCESS" "ASG $asg updated to use launch template with multiple instance types"
                    else
                        log "ERROR" "Failed to update ASG $asg to use launch template with multiple instance types"
                    fi
                else
                    log "ERROR" "Failed to create launch template from launch configuration $launch_config"
                fi
            else
                log "ERROR" "ASG $asg does not have a launch template or configuration"
            fi
        else
            log "SUCCESS" "ASG $asg already uses multiple instance types"
        fi

        # Check multi-AZ configuration
        if [[ "$az_count" -lt 2 ]]; then
            log "WARNING" "ASG $asg is using only $az_count AZ(s). Updating to use multiple AZs..."
            
            # Get VPC ID
            vpc_id=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
                --query "AutoScalingGroups[0].VPCZoneIdentifier" --output text | cut -d ',' -f1 | 
                xargs aws ec2 describe-subnets --subnet-ids --query "Subnets[0].VpcId" --output text)
            
            if [[ -n "$vpc_id" ]]; then
                # Get available AZs
                available_azs=$(aws ec2 describe-availability-zones --query "AvailabilityZones[*].ZoneName" --output text)
                
                # Get current subnet
                current_subnet_ids=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
                    --query "AutoScalingGroups[0].VPCZoneIdentifier" --output text)
                
                # Find subnets in different AZs
                new_subnet_ids="$current_subnet_ids"
                subnets_added=0
                
                # Get all subnets in the VPC
                vpc_subnets=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" --output json)
                
                # Try to find subnets in different AZs
                for az in $available_azs; do
                    # Skip if we already have enough AZs
                    if [[ "$subnets_added" -ge 2 ]]; then
                        break
                    fi
                    
                    # Look for a subnet in this AZ
                    subnet_id=$(echo $vpc_subnets | jq -r --arg az "$az" '.Subnets[] | select(.AvailabilityZone == $az) | .SubnetId' | head -1)
                    
                    if [[ -n "$subnet_id" && "$new_subnet_ids" != *"$subnet_id"* ]]; then
                        if [[ -z "$new_subnet_ids" ]]; then
                            new_subnet_ids="$subnet_id"
                        else
                            new_subnet_ids="$new_subnet_ids,$subnet_id"
                        fi
                        subnets_added=$((subnets_added + 1))
                    fi
                done
                
                # Update ASG with multiple subnets
                if [[ "$new_subnet_ids" != "$current_subnet_ids" ]]; then
                    aws autoscaling update-auto-scaling-group --auto-scaling-group-name "$asg" \
                        --vpc-zone-identifier "$new_subnet_ids"
                    
                    if [ $? -eq 0 ]; then
                        log "SUCCESS" "ASG $asg updated to use multiple AZs"
                    else
                        log "ERROR" "Failed to update ASG $asg to use multiple AZs"
                    fi
                else
                    log "WARNING" "Could not find suitable subnets in different AZs for ASG $asg"
                fi
            else
                log "ERROR" "Could not determine VPC for ASG $asg"
            fi
        else
            log "SUCCESS" "ASG $asg already spans multiple AZs ($az_count AZs)"
        fi
    done
}

# Function to check Auto Scaling launch configurations for sensitive data in
