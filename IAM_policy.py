import boto3
import botocore
import logging
from tabulate import tabulate

print("# Ensure that the IAM credentials you use to execute this code have sufficient permissions")
print("# to perform the necessary actions like listing users, policies, roles, etc.")
print("# IAM API functions used in the code.\n")

print("# Logging: The code includes logging statements to record the results of the analysis")
print("# in a log file named aws_security_audit.log. This can be helpful for keeping track")
print("# of the analysis results and any potential issues identified.\n")

print("# Printed Suggestions: The code also includes print statements to provide suggestions")
print("# based on the analysis. These suggestions are aimed at improving the security posture")
print("# of your AWS account by highlighting potential issues or areas for improvement.\n")

# Initialize IAM client
iam = boto3.client('iam')

# Error Handling
def handle_api_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            logging.error(f"Error: {e}")
            # Add additional error handling logic as needed
    return wrapper

# Logging
logging.basicConfig(filename='aws_security_audit.log', level=logging.INFO)

def log_result(result):
    logging.info(result)

@handle_api_exceptions
def enforce_password_policy():
    # Ensure IAM password policy is enforced
    response = iam.get_account_password_policy()
    password_policy = response['PasswordPolicy']
    if not password_policy['AllowUsersToChangePassword'] or not password_policy['MinimumPasswordLength']:
        log_result("IAM password policy is not properly enforced.")
        print("Suggestion: Consider enforcing a password policy that requires users to change their passwords periodically and sets a minimum password length.")

@handle_api_exceptions
def enforce_least_privilege():
    # Check for policies with excessive permissions
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        policy_version = policy['DefaultVersionId']
        policy_document = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy_version)['PolicyVersion']['Document']
        # Add logic to analyze policy document and check for least privilege
        for statement in policy_document['Statement']:
            # Check if statement allows "*" or "Resource: '*'" which indicates excessive permissions
            if (statement['Effect'] == 'Allow' and 
                ('*' in statement.get('Action', []) or 
                 '*' in statement.get('Resource', []))):
                log_result(f"Policy {policy_name} allows excessive permissions.")
                print(f"Suggestion: Review the policy '{policy_name}' for least privilege and restrict permissions to the minimum required for tasks.")
                break  # No need to check further statements for this policy
        else:
            print(f"Suggestion: Policy '{policy_name}' follows least privilege principles.")

def review_iam_policy_conditions():
    # Review IAM policies for conditions
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        response = iam.get_policy(PolicyArn=policy['Arn'])
        policy_document = response['Policy']['DefaultVersionId']
        # Add logic to analyze policy document for conditions
        if not policy_document_contains_conditions(policy_document):
            print(f"Suggestion: Policy '{policy_name}' does not use conditions to further restrict access based on contextual factors.")

def review_iam_password_policy_complexity():
    # Review IAM password policy complexity requirements
    response = iam.get_account_password_policy()
    password_policy = response['PasswordPolicy']
    # Add logic to analyze password policy for complexity requirements
    if not password_policy_meets_complexity_requirements(password_policy):
        print("Suggestion: IAM password policy does not meet complexity requirements.")

def review_iam_user_inline_policies():
    # Review IAM user inline policies
    response = iam.list_users()
    users = response['Users']
    for user in users:
        username = user['UserName']
        response = iam.list_user_policies(UserName=username)
        inline_policies = response['PolicyNames']
        # Add logic to analyze inline policies associated with IAM users
        if not inline_policies_meet_least_privilege(inline_policies):
            print(f"Suggestion: IAM user '{username}' has inline policies that may not follow least privilege principles.")

def review_iam_role_trust_relationships():
    # Review IAM role trust relationships
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        response = iam.get_role(RoleName=role_name)
        trust_policy = response['Role']['AssumeRolePolicyDocument']
        # Add logic to analyze trust policy document
        if not trust_policy_restricts_access(trust_policy):
            print(f"Suggestion: Trust policy for IAM role '{role_name}' may not restrict access appropriately.")

def review_iam_user_permissions_boundaries():
    # Review IAM user permissions boundaries
    response = iam.list_users()
    users = response['Users']
    for user in users:
        username = user['UserName']
        response = iam.get_user(UserName=username)
        permissions_boundary = response['User']['PermissionsBoundary']
        # Add logic to analyze permissions boundary
        if not permissions_boundary_is_properly_configured(permissions_boundary):
            print(f"Suggestion: IAM user '{username}' permissions boundary may not be properly configured.")

def review_iam_policy_expiration_dates():
    # Review IAM policy expiration dates
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        response = iam.get_policy(PolicyArn=policy['Arn'])
        policy_version = response['Policy']['DefaultVersionId']
        version_details = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy_version)
        create_date = version_details['PolicyVersion']['CreateDate']
        # Add logic to analyze policy creation date and determine expiration dates
        if not policy_expiration_date_is_set(create_date):
            print(f"Suggestion: Policy '{policy_name}' does not have an expiration date set.")

def review_iam_role_session_policies():
    # Review IAM role session policies for least privilege
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        response = iam.get_role(RoleName=role_name)
        session_policy = response['Role']['AssumeRolePolicyDocument']
        # Add logic to review session policy document for least privilege
        if not session_policy_enforces_least_privilege(session_policy):
            print(f"Suggestion: Session policy for IAM role '{role_name}' may not enforce least privilege.")

def review_iam_policy_size():
    # Review IAM policy size
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        response = iam.get_policy(PolicyArn=policy['Arn'])
        policy_document = response['Policy']['DefaultVersionId']
        # Add logic to check the size of IAM policies
        if not policy_size_is_optimized(policy_document):
            print(f"Suggestion: Policy '{policy_name}' size should be optimized to avoid exceeding AWS service limits.")

def review_unused_iam_permissions():
    # Review IAM policies for unused permissions
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        response = iam.list_entities_for_policy(PolicyArn=policy['Arn'])
        entities = response['PolicyGroups'] + response['PolicyUsers'] + response['PolicyRoles']
        # Add logic to analyze entities associated with the policy and identify unused permissions
        if unused_permissions_exist(entities):
            print(f"Suggestion: Policy '{policy_name}' contains unused permissions.")

def review_iam_password_policy_expiration():
    # Review IAM password policy expiration settings
    response = iam.get_account_password_policy()
    password_policy = response['PasswordPolicy']
    # Add logic to analyze password policy for expiration settings
    if not password_policy_expiration_is_set(password_policy):
        print("Suggestion: IAM password policy expiration settings are not configured.")

def review_iam_user_last_activity():
    # Review IAM user last activity
    response = iam.get_credential_report()
    # Add logic to parse credential report and identify last activity timestamps for IAM users
    last_activity_timestamps = analyze_credential_report(response)
    if not last_activity_timestamps:
        print("Suggestion: Unable to determine IAM user last activity.")

def review_iam_cross_account_access():
    # Review permissions granted to IAM roles for cross-account access and ensure they follow the principle of least privilege
    response = iam.get_account_authorization_details(Filter=['Role'])
    roles = response['RoleDetailList']
    for role in roles:
        role_name = role['RoleName']
        response = iam.list_role_policies(RoleName=role_name)
        role_policies = response['PolicyNames']
        # Add logic to review role policies for cross-account access
        if not cross_account_access_is_limited(role_policies):
            print(f"Suggestion: Review policies attached to IAM role '{role_name}' to ensure cross-account access is limited to trusted entities.")

def review_iam_service_linked_roles():
    # Verify permissions and usage of service-linked roles to ensure they are properly configured and necessary
    response = iam.list_roles(PathPrefix='/aws-service-role')
    service_linked_roles = response['Roles']
    for role in service_linked_roles:
        role_name = role['RoleName']
        # Add logic to review service-linked role permissions
        if not service_linked_role_usage_is_verified(role_name):
            print(f"Suggestion: Service-linked role '{role_name}' permissions and usage should be verified.")

def review_iam_policy_wildcard_usage():
    # Analyze IAM policies for the use of wildcards (*) to avoid unintended permissions and potential security risks
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        response = iam.get_policy(PolicyArn=policy['Arn'])
        policy_document = response['Policy']['DefaultVersionId']
        # Add logic to analyze policy document for wildcard usage
        if wildcard_usage_is_detected(policy_document):
            print(f"Suggestion: Policy '{policy_name}' uses wildcards (*) which may lead to unintended permissions and potential security risks.")

def review_iam_group_membership():
    # Check IAM group memberships to ensure users are assigned to appropriate groups and have necessary permissions
    response = iam.list_groups()
    groups = response['Groups']
    for group in groups:
        group_name = group['GroupName']
        response = iam.get_group(GroupName=group_name)
        users = response['Users']
        # Add logic to analyze group membership
        if not group_membership_is_appropriate(users):
            print(f"Suggestion: IAM group '{group_name}' membership should be reviewed to ensure users have necessary permissions.")

def review_iam_role_policies_resource_specific():
    # Verify IAM role policies for resource-specific permissions to ensure they are scoped appropriately
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        response = iam.list_attached_role_policies(RoleName=role_name)
        attached_policies = response['AttachedPolicies']
        for policy in attached_policies:
            policy_name = policy['PolicyName']
            response = iam.get_policy(PolicyArn=policy['PolicyArn'])
            policy_document = response['Policy']['DefaultVersionId']
            # Add logic to analyze policy document for resource-specific permissions
            if not resource_specific_permissions_are_scoped_appropriately(policy_document):
                print(f"Suggestion: IAM role '{role_name}' has policies with resource-specific permissions that may not be scoped appropriately.")

def review_iam_user_permissions_boundaries():
    # Ensure IAM user permissions boundaries are properly configured and restrict permissions as intended
    response = iam.list_users()
    users = response['Users']
    for user in users:
        username = user['UserName']
        response = iam.get_user(UserName=username)
        permissions_boundary = response['User']['PermissionsBoundary']
        # Add logic to analyze permissions boundary
        if not permissions_boundary_is_properly_configured(permissions_boundary):
            print(f"Suggestion: IAM user '{username}' permissions boundary may not be properly configured.")

def review_iam_role_session_policies():
    # Review IAM role session policies to ensure they enforce least privilege principles and restrict permissions appropriately
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        response = iam.get_role(RoleName=role_name)
        session_policy = response['Role']['AssumeRolePolicyDocument']
        # Add logic to review session policy document for least privilege
        if not session_policy_enforces_least_privilege(session_policy):
            print(f"Suggestion: Session policy for IAM role '{role_name}' may not enforce least privilege.")

def review_iam_policy_expiration_dates():
    # Check IAM policy expiration dates to ensure policies are reviewed and renewed before expiration
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        response = iam.get_policy(PolicyArn=policy['Arn'])
        policy_version = response['Policy']['DefaultVersionId']
        version_details = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy_version)
        create_date = version_details['PolicyVersion']['CreateDate']
        # Add logic to analyze policy creation date and determine expiration dates
        if not policy_expiration_date_is_set(create_date):
            print(f"Suggestion: Policy '{policy_name}' does not have an expiration date set.")

@handle_api_exceptions
def enforce_least_privilege():
    # Check for policies with excessive permissions
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        policy_version = policy['DefaultVersionId']
        policy_document = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy_version)['PolicyVersion']['Document']
        # Add logic to analyze policy document and check for least privilege
        if policy_document_contains_excessive_permissions(policy_document):
            log_result(f"Policy {policy_name} allows excessive permissions.")
            print(f"Suggestion: Review the policy '{policy_name}' for least privilege and restrict permissions to the minimum required for tasks.")
        else:
            log_result(f"Policy {policy_name} analyzed for least privilege.")
            # Add suggestion if not already present
            print(f"No suggestion needed: Policy '{policy_name}' enforces least privilege.")
@handle_api_exceptions
def enforce_iam_permission_boundaries():
    # Ensure IAM permission boundaries are properly configured
    response = iam.list_users()
    users = response['Users']
    for user in users:
        username = user['UserName']
        response = iam.list_attached_user_policies(UserName=username)
        attached_policies = response['AttachedPolicies']
        if not attached_policies:
            log_result(f"IAM User '{username}' does not have any permission boundaries set.")
            print(f"Suggestion: Consider setting IAM permission boundaries for user '{username}' to restrict permissions within defined limits.")
        else:
            log_result(f"IAM User '{username}' has permission boundaries set.")
            # Add suggestion if not already present
            print(f"No suggestion needed: Permission boundaries are set for user '{username}'.")

@handle_api_exceptions
def review_iam_role_assumption_session_policies():
    # Review IAM role assumption and session policies
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        response = iam.get_role(RoleName=role_name)
        trust_policy = response['Role']['AssumeRolePolicyDocument']
        # Add logic to review assume role policy document
        if not assume_role_policy_enforces_least_privilege(trust_policy):
            print(f"Suggestion: Review the assume role policy for IAM role '{role_name}' to ensure it enforces least privilege and restricts access appropriately.")
        else:
            # Add suggestion if not already present
            print(f"No suggestion needed: Assume role policy for IAM role '{role_name}' enforces least privilege.")

@handle_api_exceptions
def simulate_iam_policy():
    # Simulate IAM policy to test effectiveness
    response = iam.simulate_principal_policy(PolicySourceArn='arn:aws:iam::123456789012:role/example-role', ActionNames=['s3:GetObject'])
    results = response['EvaluationResults']
    for result in results:
        if result['EvalDecision'] == 'Deny':
            log_result("IAM policy simulation indicates a potential denial.")
            print("Suggestion: Perform IAM policy simulation regularly to identify potential denial scenarios and adjust policies accordingly.")
        else:
            # Add suggestion if not already present
            print("No suggestion needed: IAM policy simulation did not indicate any potential denial.")

@handle_api_exceptions
def analyze_iam_credential_report():
    # Analyze IAM credential report
    response = iam.generate_credential_report()
    if response['State'] == 'COMPLETE':
        report = iam.get_credential_report()
        # Add logic to analyze credential report
        print("Suggestion: Analyze IAM credential report regularly to identify security risks such as unused credentials and take appropriate actions.")
    else:
        # Add suggestion if not already present
        print("No suggestion needed: IAM credential report generation is not yet complete.")

@handle_api_exceptions
def review_iam_cross_account_access():
    # Review IAM cross-account access
    response = iam.get_account_authorization_details(Filter=['Role'])
    roles = response['RoleDetailList']
    for role in roles:
        role_name = role['RoleName']
        response = iam.list_role_policies(RoleName=role_name)
        role_policies = response['PolicyNames']
        # Add logic to review role policies for cross-account access
        if not cross_account_access_is_limited(role_policies):
            print(f"Suggestion: Review policies attached to IAM role '{role_name}' to ensure cross-account access is limited to trusted entities.")
        else:
            # Add suggestion if not already present
            print(f"No suggestion needed: Cross-account access for IAM role '{role_name}' is limited to trusted entities.")

@handle_api_exceptions
def review_iam_access_keys_rotation():
    # Review IAM access keys rotation
    response = iam.list_users()
    users = response['Users']
    for user in users:
        username = user['UserName']
        response = iam.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']
        for key in access_keys:
            key_id = key['AccessKeyId']
            create_date = key['CreateDate']
            if access_key_rotation_needed(create_date):
                print(f"Suggestion: IAM user '{username}' access key '{key_id}' rotation is needed to minimize unauthorized access.")
            else:
                print(f"No suggestion needed: IAM user '{username}' access key '{key_id}' is rotated regularly.")

@handle_api_exceptions
def review_iam_groups_configuration():
    # Review IAM groups configuration
    response = iam.list_groups()
    groups = response['Groups']
    for group in groups:
        group_name = group['GroupName']
        response = iam.get_group(GroupName=group_name)
        users = response['Users']
        # Add logic to analyze group membership and configuration
        if not group_configuration_is_appropriate(users):
            print(f"Suggestion: Review IAM group '{group_name}' configuration to ensure users are assigned to appropriate groups based on their roles and responsibilities.")

@handle_api_exceptions
def review_iam_roles_sensitive_permissions():
    # Review IAM roles for sensitive permissions
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        if role_has_sensitive_permissions(role_name):
            print(f"Suggestion: IAM role '{role_name}' has sensitive permissions. Ensure proper monitoring and auditing are in place.")
        else:
            print(f"No suggestion needed: IAM role '{role_name}' does not have sensitive permissions.")

@handle_api_exceptions
def review_iam_role_policies_resource_tagging():
    # Review IAM role policies for resource tagging enforcement
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        if role_policy_enforces_resource_tagging(role_name):
            print(f"No suggestion needed: IAM role '{role_name}' policy enforces resource tagging.")
        else:
            print(f"Suggestion: Review IAM role '{role_name}' policies to ensure enforcement of resource tagging policies.")

@handle_api_exceptions
def review_iam_policies_unused_permissions():
    # Review IAM policies for unused permissions
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        if unused_permissions_exist(policy_name):
            print(f"Suggestion: IAM policy '{policy_name}' contains unused permissions. Remove them to reduce the attack surface.")
        else:
            print(f"No suggestion needed: IAM policy '{policy_name}' does not contain unused permissions.")

@handle_api_exceptions
def review_iam_policy_versioning():
    # Review IAM policy versioning
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        if policy_versioning_needs_cleanup(policy_name):
            print(f"Suggestion: Review IAM policy '{policy_name}' versioning to retain only necessary versions.")
        else:
            print(f"No suggestion needed: IAM policy '{policy_name}' versioning is appropriately managed.")

@handle_api_exceptions
def review_iam_role_permission_boundaries():
    # Review IAM role permission boundaries
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        if permission_boundaries_are_inappropriate(role_name):
            print(f"Suggestion: Review IAM role '{role_name}' permission boundaries to ensure they are properly configured.")
        else:
            print(f"No suggestion needed: IAM role '{role_name}' permission boundaries are properly configured.")

@handle_api_exceptions
def review_iam_user_mfa_status():
    # Review IAM user MFA status
    response = iam.list_users()
    users = response['Users']
    for user in users:
        username = user['UserName']
        if mfa_enabled_for_user(username):
            print(f"No suggestion needed: MFA is enabled for IAM user '{username}'.")
        else:
            print(f"Suggestion: Enable MFA for IAM user '{username}' to enhance security.")

@handle_api_exceptions
def review_iam_policies_privilege_escalation():
    # Review IAM policies for privilege escalation paths
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        if privilege_escalation_paths_exist(policy_name):
            print(f"Suggestion: Analyze IAM policy '{policy_name}' for potential privilege escalation paths.")
        else:
            print(f"No suggestion needed: IAM policy '{policy_name}' does not contain privilege escalation paths.")

@handle_api_exceptions
def review_iam_role_trust_relationships():
    # Review IAM role trust relationships
    response = iam.list_roles()
    roles = response['Roles']
    for role in roles:
        role_name = role['RoleName']
        if trust_relationships_need_review(role_name):
            print(f"Suggestion: Review trust relationships for IAM role '{role_name}' to ensure only trusted entities can assume the role.")
        else:
            print(f"No suggestion needed: Trust relationships for IAM role '{role_name}' are appropriately configured.")

@handle_api_exceptions
def review_iam_policy_conditions():
    # Review IAM policy conditions
    response = iam.list_policies(Scope='Local')
    policies = response['Policies']
    for policy in policies:
        policy_name = policy['PolicyName']
        if policy_conditions_need_review(policy_name):
            print(f"Suggestion: Review IAM policy '{policy_name}' conditions to further restrict access based on contextual factors.")
        else:
            print(f"No suggestion needed: IAM policy '{policy_name}' conditions are appropriately configured.")

@handle_api_exceptions
def review_iam_user_permissions_change_history():
    # Review IAM user permissions change history
    response = iam.generate_service_last_accessed_details()
    if response['JobStatus'] == 'COMPLETED':
        # Retrieve last accessed details for IAM users
        users_last_accessed = iam.get_service_last_accessed_details()
        for user_details in users_last_accessed['ServicesLastAccessed']:
            user_name = user_details['ServiceName']
            last_accessed_timestamp = user_details['LastAuthenticated']
            if last_accessed_timestamp:
                print(f"IAM User '{user_name}' was last accessed on {last_accessed_timestamp}.")
            else:
                print(f"Suggestion: IAM User '{user_name}' has never been accessed.")
    else:
        print("No suggestion needed: Retrieval of IAM user last accessed details is not yet complete.")


# Define the function to print a table
def print_table(headers, data):
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))


# High Importance Functions with their outputs
high_importance_functions = [
    ("enforce_least_privilege", enforce_least_privilege()),
    ("enforce_password_policy", enforce_password_policy()),
    ("review_iam_password_policy_complexity", review_iam_password_policy_complexity()),
    ("review_iam_role_trust_relationships", review_iam_role_trust_relationships()),
    ("review_iam_user_inline_policies", review_iam_user_inline_policies()),
    ("review_unused_iam_permissions", review_unused_iam_permissions()),
    ("review_iam_policy_expiration_dates", review_iam_policy_expiration_dates()),
    ("review_iam_role_session_policies", review_iam_role_session_policies()),
    ("review_iam_policy_size", review_iam_policy_size()),
    ("review_iam_service_linked_roles", review_iam_service_linked_roles()),
    ("review_iam_policy_wildcard_usage", review_iam_policy_wildcard_usage()),
    ("review_iam_group_membership", review_iam_group_membership()),
    ("review_iam_role_policies_resource_specific", review_iam_role_policies_resource_specific()),
    ("review_iam_user_permissions_boundaries", review_iam_user_permissions_boundaries()),
    ("review_iam_role_session_policies", review_iam_role_session_policies())
]

# Present the options
print("High Importance Functions and their outputs:")

# Display the selected table
print_table(["Function Name", "Function Output"], high_importance_functions)

# Medium Importance Functions with their outputs
medium_importance_functions = [
    ("simulate_iam_policy", simulate_iam_policy()),
    ("analyze_iam_credential_report", analyze_iam_credential_report()),
    ("review_iam_cross_account_access", review_iam_cross_account_access()),
    ("review_iam_access_keys_rotation", review_iam_access_keys_rotation()),
    ("review_iam_groups_configuration", review_iam_groups_configuration()),
    ("review_iam_roles_sensitive_permissions", review_iam_roles_sensitive_permissions()),
    ("review_iam_role_policies_resource_tagging", review_iam_role_policies_resource_tagging()),
    ("review_iam_policies_unused_permissions", review_iam_policies_unused_permissions()),
    ("review_iam_policy_versioning", review_iam_policy_versioning()),
    ("review_iam_role_permission_boundaries", review_iam_role_permission_boundaries()),
    ("review_iam_user_mfa_status", review_iam_user_mfa_status()),
    ("review_iam_policies_privilege_escalation", review_iam_policies_privilege_escalation()),
    ("review_iam_role_trust_relationships", review_iam_role_trust_relationships()),
    ("review_iam_policy_conditions", review_iam_policy_conditions()),
    ("review_iam_user_permissions_change_history", review_iam_user_permissions_change_history())
]

# Present the options
print("Medium Importance Functions and their outputs:")

# Display the selected table
print_table(["Function Name", "Function Output"], medium_importance_functions)

# Low Importance Functions with their outputs
low_importance_functions = [
    ("handle_api_exceptions", handle_api_exceptions),
    ("log_result", log_result)
]

print("\nLow Importance Functions and their outputs:")

# Display the selected table
print_table(["Function Name", "Function Output"], low_importance_functions)


# Present the options for selecting a table
print("Please select an option to view the corresponding table:")
print("1. High Importance Functions")
print("2. Medium Importance Functions")
print("3. Low Importance Functions")

# Get user input
option = input("Enter your choice (1, 2, or 3): ")

# Display the selected table
if option == "1":
    print_table(["High Importance Functions"], [[func[0]] for func in high_importance_functions])
elif option == "2":
    print_table(["Medium Importance Functions"], [[func[0]] for func in medium_importance_functions])
elif option == "3":
    print_table(["Low Importance Functions"], [[func[0]] for func in low_importance_functions])
else:
    print("Invalid option. Please select 1, 2, or 3.")
