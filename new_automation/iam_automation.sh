#!/bin/bash
# Function to disable IAM Access Analyzer in all regions
disable_iam_access_analyzer() {
  echo "Disabling IAM Access Analyzer in all regions"
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "Checking for Access Analyzer in region: $region"
    analyzer_name=$(aws accessanalyzer list-analyzers --region "$region" --query "analyzers[?name=='default-analyzer'].name" --output text)
    if [[ -n "$analyzer_name" ]]; then
      echo "Disabling Access Analyzer: $analyzer_name in region $region"
      aws accessanalyzer delete-analyzer --analyzer-name "$analyzer_name" --region "$region"
    else
      echo "No Access Analyzer found in region $region"
    fi
  done
}
# Function to ensure IAM Access Analyzer is enabled in all regions
enable_iam_access_analyzer() {
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "Enabling Access Analyzer in region: $region"
    aws accessanalyzer create-analyzer --analyzer-name "default-analyzer" --type ACCOUNT --region "$region" 2>/dev/null || echo "Access Analyzer already exists in $region"
  done
}
# Function to ensure IAM Access Analyzer has no findings
check_access_analyzer_findings() {
  for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "Checking Access Analyzer findings in region: $region"
    analyzer_arn=$(aws accessanalyzer list-analyzers --region "$region" --query "analyzers[?name=='default-analyzer'].arn" --output text)
    if [[ -z "$analyzer_arn" ]]; then
      echo "No Access Analyzer found in region $region. Skipping."
      continue
    fi
    findings=$(aws accessanalyzer list-findings --analyzer-arn "$analyzer_arn" --region "$region" --query "findings" --output json)
    if [[ "$findings" != "[]" ]]; then
      echo "Findings exist in $region: $findings"
      echo "Removing findings in $region"
      for finding_id in $(aws accessanalyzer list-findings --analyzer-arn "$analyzer_arn" --region "$region" --query "findings[].id" --output text); do
         aws accessanalyzer update-findings --analyzer-arn "$analyzer_arn" --ids "$finding_id" --status ARCHIVED --region "$region"
      done
    else
      echo "No findings in $region"
    fi
  done
}
# Function to set IAM password policy
set_iam_password_policy() {
  echo "Setting IAM password policy"
  aws iam update-account-password-policy \
    --minimum-password-length 14 \
    --require-lowercase-characters \
    --require-uppercase-characters \
    --require-numbers \
    --require-symbols \
    --password-reuse-prevention 5 \
    --max-password-age 90
}
# Function to check unattached custom policies for admin access and remove it if found
check_unattached_admin_policies() {
  echo "Checking unattached custom policies for admin access"
  for policy_arn in $(aws iam list-policies --scope Local --query "Policies[?AttachmentCount==\`0\`].Arn" --output text); do
    # Fetch the default version ID of the policy
    version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query "Policy.DefaultVersionId" --output text)

    # Retrieve the policy document
    statements=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query "PolicyVersion.Document.Statement" --output json)

    # Check for admin privileges in the policy document
    is_admin=$(echo "$statements" | jq -e 'if type=="array" then .[] else . end | select(.Effect=="Allow" and .Action=="*" and .Resource=="*")')

    if [[ $? -eq 0 ]]; then
      echo "Policy $policy_arn has admin access. Deleting it."
      aws iam delete-policy --policy-arn "$policy_arn"
    else
      echo "Policy $policy_arn does not have admin access."
    fi
  done
}
ensure_iam_groups_have_users_or_remove() {
  echo "Ensuring IAM groups have at least one user or removing the group"
  for group_name in $(aws iam list-groups --query "Groups[].GroupName" --output text); do
    user_count=$(aws iam get-group --group-name "$group_name" --query "Users | length(@)" --output text)
    if [[ "$user_count" -eq 0 ]]; then
      echo "Group $group_name has no users."
      read -p "Do you want to (A)dd a user or (R)emove the group? [A/R]: " choice
      if [[ "$choice" == "A" || "$choice" == "a" ]]; then
        read -p "Enter the username to add: " username
        user_exists=$(aws iam get-user --user-name "$username" 2>/dev/null)
        if [[ $? -eq 0 ]]; then
          echo "User $username already exists."
        else
          echo "User $username does not exist. Creating user."
          aws iam create-user --user-name "$username"
        fi
        aws iam add-user-to-group --user-name "$username" --group-name "$group_name"
        echo "User $username added to group $group_name."
      elif [[ "$choice" == "R" || "$choice" == "r" ]]; then
        echo "Detaching policies from group $group_name before deletion."
        for policy_arn in $(aws iam list-attached-group-policies --group-name "$group_name" --query "AttachedPolicies[].PolicyArn" --output text); do
          aws iam detach-group-policy --group-name "$group_name" --policy-arn "$policy_arn"
          echo "Detached policy $policy_arn from group $group_name."
        done
        aws iam delete-group --group-name "$group_name"
        echo "Group $group_name has been removed."
      else
        echo "Invalid choice. Skipping group $group_name."
      fi
    else
      echo "Group $group_name has $user_count user(s)"
    fi
  done
}

# Function to check for inline policies with administrative privileges and remove them
check_inline_policies_for_admin_privileges() {
  echo "Checking inline policies for admin privileges"
  for role_name in $(aws iam list-roles --query "Roles[].RoleName" --output text); do
    for policy_name in $(aws iam list-role-policies --role-name "$role_name" --query "PolicyNames" --output text); do
      statements=$(aws iam get-role-policy --role-name "$role_name" --policy-name "$policy_name" --query "PolicyDocument.Statement" --output json)
      is_admin=$(echo "$statements" | jq -e 'if type=="array" then .[] else . end | select(.Effect=="Allow" and .Action=="*" and .Resource=="*")')
      if [[ $? -eq 0 ]]; then
        echo "Inline policy $policy_name in role $role_name has admin privileges. Deleting it."
        aws iam delete-role-policy --role-name "$role_name" --policy-name "$policy_name"
      else
        echo "Inline policy $policy_name in role $role_name does not have admin privileges."
      fi
    done
  done
}
# Function to ensure AWS-managed policies are attached to roles
check_managed_policies_attached() {
  echo "Ensuring AWS-managed policies are attached to roles"
  for role_name in $(aws iam list-roles --query "Roles[].RoleName" --output text); do
    attached_policies=$(aws iam list-attached-role-policies --role-name "$role_name" --query "AttachedPolicies[].PolicyArn" --output text)
    if [[ -z "$attached_policies" ]]; then
      echo "No AWS-managed policies attached to role $role_name."
      read -p "Do you want to attach a managed policy to this role? [Y/N]: " choice
      if [[ "$choice" == "Y" || "$choice" == "y" ]]; then
        read -p "Enter the ARN of the managed policy to attach: " policy_arn
        aws iam attach-role-policy --role-name "$role_name" --policy-arn "$policy_arn"
        echo "Managed policy $policy_arn attached to role $role_name."
      else
        echo "No managed policy attached to role $role_name. Skipping."
      fi
    else
      echo "Role $role_name has AWS-managed policies attached"
    fi
  done
}
# Function to detach and delete policies granting full access
detach_and_delete_full_access_policies() {
  echo "Auditing IAM policies to detach and delete policies granting full access"
  for policy_arn in $(aws iam list-policies --scope Local --query "Policies[].Arn" --output text); do
    version_id=$(aws iam get-policy --policy-arn "$policy_arn" --query "Policy.DefaultVersionId" --output text)
    statements=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query "PolicyVersion.Document.Statement" --output json)
    is_full_access=$(echo "$statements" | jq -e 'if type=="array" then .[] else . end | select(.Effect=="Allow" and .Action=="*" and .Resource=="*")')

    if [[ $? -eq 0 ]]; then
      echo "Policy $policy_arn grants full access. Detaching it from all entities."

      # Detach from roles
      for role in $(aws iam list-entities-for-policy --policy-arn "$policy_arn" --query "PolicyRoles[].RoleName" --output text); do
        echo "Detaching policy $policy_arn from role $role"
        aws iam detach-role-policy --role-name "$role" --policy-arn "$policy_arn"
      done

      # Detach from users
      for user in $(aws iam list-entities-for-policy --policy-arn "$policy_arn" --query "PolicyUsers[].UserName" --output text); do
        echo "Detaching policy $policy_arn from user $user"
        aws iam detach-user-policy --user-name "$user" --policy-arn "$policy_arn"
      done

      # Detach from groups
      for group in $(aws iam list-entities-for-policy --policy-arn "$policy_arn" --query "PolicyGroups[].GroupName" --output text); do
        echo "Detaching policy $policy_arn from group $group"
        aws iam detach-group-policy --group-name "$group" --policy-arn "$policy_arn"
      done

      # Delete the policy
      echo "Deleting policy $policy_arn"
      aws iam delete-policy --policy-arn "$policy_arn"
    else
      echo "Policy $policy_arn does not grant full access."
    fi
  done
}
# Delete policies granting full access to CloudTrail and KMS services
delete_policies_with_full_access_cloudtrail_kms() {
    echo "Checking for IAM policies with full access to CloudTrail and KMS services..."
    policies=$(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text)

    for policy_arn in $policies; do
        policy_version=$(aws iam get-policy --policy-arn $policy_arn --query 'Policy.DefaultVersionId' --output text)
        policy_document=$(aws iam get-policy-version --policy-arn $policy_arn --version-id $policy_version --query 'PolicyVersion.Document' --output json)

        if echo "$policy_document" | grep -q 'cloudtrail:*' || echo "$policy_document" | grep -q 'kms:*'; then
            echo "Policy $policy_arn grants full access to CloudTrail or KMS. Deleting..."
            aws iam delete-policy --policy-arn $policy_arn
            echo "Deleted policy: $policy_arn"
        fi
    done
}
# Detach AdministratorAccess policy from IAM roles
detach_admin_access_policy() {
    echo "Checking for IAM roles with AdministratorAccess policy attached..."
    roles=$(aws iam list-roles --query 'Roles[].RoleName' --output text)

    for role in $roles; do
        attached_policies=$(aws iam list-attached-role-policies --role-name $role --query 'AttachedPolicies[].PolicyArn' --output text)

        if echo "$attached_policies" | grep -q 'AdministratorAccess'; then
            echo "Role $role has AdministratorAccess policy attached. Detaching..."
            aws iam detach-role-policy --role-name $role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
            echo "Detached AdministratorAccess policy from role: $role"
        fi
    done
}
# Delete IAM roles not used in the last 60 days
delete_unused_roles() {
    echo "Checking for IAM roles not used in the last 60 days..."
    roles=$(aws iam list-roles --query 'Roles[].RoleName' --output text)

    for role in $roles; do
        # Get the last used date of the role
        last_used=$(aws iam get-role --role-name $role --query 'Role.RoleLastUsed.LastUsedDate' --output text 2>/dev/null)

        # If last used date is not available or is older than 60 days, delete the role
        if [[ -z "$last_used" || $(date -d "$last_used" +%s) -lt $(date -d '60 days ago' +%s) ]]; then
            echo "Role $role has not been used in the last 60 days. Deleting..."

            # Detach any attached policies before deletion
            attached_policies=$(aws iam list-attached-role-policies --role-name $role --query 'AttachedPolicies[].PolicyArn' --output text)
            for policy_arn in $attached_policies; do
                echo "Detaching policy $policy_arn from role $role..."
                aws iam detach-role-policy --role-name $role --policy-arn $policy_arn
            done

            # Delete the inline policies if any
            inline_policies=$(aws iam list-role-policies --role-name $role --query 'PolicyNames' --output text)
            for inline_policy in $inline_policies; do
                echo "Deleting inline policy $inline_policy from role $role..."
                aws iam delete-role-policy --role-name $role --policy-name $inline_policy
            done

            # Finally, delete the role
            aws iam delete-role --role-name $role
            echo "Deleted role: $role"
        else
            echo "Role $role has been used recently (Last Used: $last_used). Skipping..."
        fi
    done
}
# Delete custom policies that are not attached to any entity
delete_unused_custom_policies() {
    echo "Checking for unused custom IAM policies..."

    # Get all local (custom) policy ARNs
    policies=$(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text)

    for policy_arn in $policies; do
        echo "Checking policy: $policy_arn..."

        # Check if the policy is attached to any groups, users, or roles
        attachments=$(aws iam list-entities-for-policy --policy-arn $policy_arn --query 'PolicyGroups | length(@) + PolicyUsers | length(@) + PolicyRoles | length(@)' --output text)

        if [[ $attachments -eq 0 ]]; then
            echo "Policy $policy_arn is not attached to any entity. Deleting..."

            # Attempt to delete the policy
            aws iam delete-policy --policy-arn $policy_arn
            if [[ $? -eq 0 ]]; then
                echo "Deleted unused custom policy: $policy_arn"
            else
                echo "Failed to delete policy: $policy_arn. Check for potential conflicts."
            fi
        else
            echo "Policy $policy_arn is attached to entities and cannot be deleted."
        fi
    done
}
# Delete Access Keys for Root User
delete_root_access_keys() {
    echo "Checking for access keys on the root user..."
    keys=$(aws iam list-access-keys --user-name root --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
    for key in $keys; do
        echo "Deleting access key $key for the root user..."
        aws iam delete-access-key --user-name root --access-key-id $key
        echo "Access key $key deleted."
    done
}

# Remove Expired SSL/TLS Certificates
remove_expired_certificates() {
    echo "Checking for expired SSL/TLS certificates..."
    certs=$(aws iam list-server-certificates --query 'ServerCertificateMetadataList[?Expiration<=`date +%Y-%m-%dT%H:%M:%SZ`].ServerCertificateName' --output text)
    for cert in $certs; do
        echo "Deleting expired certificate: $cert..."
        aws iam delete-server-certificate --server-certificate-name $cert
        echo "Certificate $cert deleted."
    done
}				
# Create IAM Security Audit Role
create_security_audit_role() {
    echo "Creating IAM Security Audit role..."
    aws iam create-role --role-name SecurityAuditRole --assume-role-policy-document '{
      "Version": "2012-10-17",
      "Statement": {
        "Effect": "Allow",
        "Principal": { "Service": "ec2.amazonaws.com" },
        "Action": "sts:AssumeRole"
      }
    }'
    aws iam attach-role-policy --role-name SecurityAuditRole --policy-arn arn:aws:iam::aws:policy/SecurityAudit
    echo "IAM Security Audit role created and policy attached."
}
# Rotate IAM User Access Keys Every 90 Days
rotate_user_access_keys() {
    echo "Rotating access keys for IAM users..."
    users=$(aws iam list-users --query 'Users[].UserName' --output text)
    for user in $users; do
        keys=$(aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[].{Id:AccessKeyId,Created:CreateDate}' --output json)
        for key in $(echo $keys | jq -c '.[]'); do
            key_id=$(echo $key | jq -r '.Id')
            created=$(echo $key | jq -r '.Created')
            if [[ $(date -d "$created" +%s) -lt $(date -d '1 day ago' +%s) ]]; then
                echo "Rotating access key $key_id for user $user..."
                aws iam delete-access-key --user-name $user --access-key-id $key_id
                aws iam create-access-key --user-name $user
                echo "Access key rotated for user $user."
            fi
        done
    done
}
# Assign Access Keys and Passwords at Setup
assign_access_keys_passwords() {
    echo "Assigning access keys and passwords for IAM users..."
    users=$(aws iam list-users --query 'Users[].UserName' --output text)
    for user in $users; do
        keys=$(aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[].AccessKeyId' --output text)
        if [[ -z "$keys" ]]; then
            echo "Creating access keys for user: $user..."
            aws iam create-access-key --user-name $user
        fi

        login_profile=$(aws iam get-login-profile --user-name $user 2>/dev/null)
        if [[ $? -ne 0 ]]; then
            echo "Creating login profile for user: $user..."
            aws iam create-login-profile --user-name $user --password 'TemporaryPassword123!' --password-reset-required
        fi
    done
}
# Disable Users with Console Access Unused for 45+ Days
disable_unused_console_users() {
    echo "Generating IAM credential report..."
    aws iam generate-credential-report
    sleep 2  # Wait for the report to be generated

    echo "Retrieving credential report..."
    report=$(aws iam get-credential-report --query 'Content' --output text | base64 -d)

    # Get today's date and calculate the cutoff date (45 days ago)
    cutoff_date=$(date -d "45 days ago" +%Y-%m-%d)

    echo "Processing users with console access..."
    echo "$report" | while IFS=',' read -r user_name user_type password_last_used; do
        # Skip the header row and roles
        if [[ "$user_name" == "user" || "$user_type" == "role" ]]; then
            continue
        fi

        # Check if the password was last used and compare with cutoff date
        if [[ "$password_last_used" != "N/A" && "$password_last_used" < "$cutoff_date" ]]; then
            echo "User $user_name has not logged in since $password_last_used. Disabling console access..."
            aws iam update-login-profile --user-name "$user_name" --password-reset-required
        fi
    done
}
# Restrict AWSCloudShellFullAccess for All Users
restrict_cloudshell_access() {
    echo "Checking for users with AWSCloudShellFullAccess policy attached..."

    # List all IAM users
    users=$(aws iam list-users --query 'Users[].UserName' --output text)

    for user in $users; do
        # List attached policies for each user
        attached_policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output text)

        for policy_arn in $attached_policies; do
            if [[ "$policy_arn" == *"AWSCloudShellFullAccess"* ]]; then
                echo "Detaching AWSCloudShellFullAccess from user: $user"
                aws iam detach-user-policy --user-name "$user" --policy-arn "$policy_arn"

                if [[ $? -eq 0 ]]; then
                    echo "Successfully detached AWSCloudShellFullAccess from user: $user"
                else
                    echo "Failed to detach AWSCloudShellFullAccess from user: $user"
                fi
            fi
        done
    done

    echo "CloudShell access restriction completed."
}
enable_single_active_access_key() {
    echo "Ensuring each IAM user has only one active access key..."

    # Get the list of all IAM users
    users=$(aws iam list-users --query 'Users[].UserName' --output text)

    for user in $users; do
        echo "Checking access keys for user: $user"

        # List all access keys for the user
        access_keys=$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text)

        active_keys=0
        for key_id in $access_keys; do
            # Check the status of the access key
            key_status=$(aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?AccessKeyId=='$key_id'].Status" --output text)

            if [[ "$key_status" == "Active" ]]; then
                ((active_keys++))
                if [[ $active_keys -gt 1 ]]; then
                    echo "Disabling additional active access key $key_id for user: $user"
                    aws iam update-access-key --user-name "$user" --access-key-id "$key_id" --status Inactive
                    if [[ $? -eq 0 ]]; then
                        echo "Successfully disabled access key $key_id for user: $user"
                    else
                        echo "Failed to disable access key $key_id for user: $user"
                    fi
                fi
            fi
        done
    done

    echo "Access key restriction completed."
}
delete_inline_policies() {
    echo "Deleting inline policies associated with users, roles, and groups..."

    # Delete inline policies for IAM users
    echo "Processing IAM users..."
    users=$(aws iam list-users --query 'Users[].UserName' --output text)
    for user in $users; do
        policies=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text)
        for policy_name in $policies; do
            echo "Deleting inline policy $policy_name from user $user..."
            aws iam delete-user-policy --user-name "$user" --policy-name "$policy_name"
            if [[ $? -eq 0 ]]; then
                echo "Successfully deleted inline policy $policy_name from user $user."
            else
                echo "Failed to delete inline policy $policy_name from user $user."
            fi
        done
    done

    # Delete inline policies for IAM roles
    echo "Processing IAM roles..."
    roles=$(aws iam list-roles --query 'Roles[].RoleName' --output text)
    for role in $roles; do
        policies=$(aws iam list-role-policies --role-name "$role" --query 'PolicyNames' --output text)
        for policy_name in $policies; do
            echo "Deleting inline policy $policy_name from role $role..."
            aws iam delete-role-policy --role-name "$role" --policy-name "$policy_name"
            if [[ $? -eq 0 ]]; then
                echo "Successfully deleted inline policy $policy_name from role $role."
            else
                echo "Failed to delete inline policy $policy_name from role $role."
            fi
        done
    done

    # Delete inline policies for IAM groups
    echo "Processing IAM groups..."
    groups=$(aws iam list-groups --query 'Groups[].GroupName' --output text)
    for group in $groups; do
        policies=$(aws iam list-group-policies --group-name "$group" --query 'PolicyNames' --output text)
        for policy_name in $policies; do
            echo "Deleting inline policy $policy_name from group $group..."
            aws iam delete-group-policy --group-name "$group" --policy-name "$policy_name"
            if [[ $? -eq 0 ]]; then
                echo "Successfully deleted inline policy $policy_name from group $group."
            else
                echo "Failed to delete inline policy $policy_name from group $group."
            fi
        done
    done

    echo "Inline policy deletion completed."
}
delete_unattached_iam_policies() {
    echo "Checking for unattached IAM policies..."

    # List all custom (local) policies
    policies=$(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text)

    for policy_arn in $policies; do
        echo "Checking policy: $policy_arn"

        # Check if the policy is attached to any entities
        attached_entities=$(aws iam list-entities-for-policy --policy-arn "$policy_arn" \
            --query 'length(PolicyGroups) + length(PolicyUsers) + length(PolicyRoles)' --output text)

        if [[ "$attached_entities" -eq 0 ]]; then
            echo "Policy $policy_arn is not attached to any entities. Deleting..."
            aws iam delete-policy --policy-arn "$policy_arn"
            if [[ $? -eq 0 ]]; then
                echo "Successfully deleted policy: $policy_arn"
            else
                echo "Failed to delete policy: $policy_arn"
            fi
        else
            echo "Policy $policy_arn is attached to entities. Skipping..."
        fi
    done

    echo "Unattached IAM policy deletion completed."
}
# Execute functions
#disable_iam_access_analyzer
#enable_iam_access_analyzer
#check_access_analyzer_findings
#set_iam_password_policy
#check_managed_policies_attached
#check_unattached_admin_policies
#ensure_iam_groups_have_users_or_remove
#check_inline_policies_for_admin_privileges
#detach_and_delete_full_access_policies
#review_iam_roles   #facing error
#delete_policies_with_full_access_cloudtrail_kms
#delete_unused_custom_policies #facing error
#detach_admin_access_policy
#delete_unused_roles #facing error
#delete_root_access_keys
#remove_expired_certificates
#create_security_audit_role
#rotate_user_access_keys
#assign_access_keys_passwords
#disable_unused_console_users
#restrict_cloudshell_access
#enable_single_active_access_key
#delete_inline_policies
#delete_unattached_iam_policies		
		
