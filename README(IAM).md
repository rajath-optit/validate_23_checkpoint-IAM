
** Ensure that the IAM credentials you use to execute this code have sufficient permissions to perform the necessary actions like listing users, policies, roles, etc. IAM API functions used in the code.**

** Logging: The code includes logging statements to record the results of the analysis in a log file named aws_security_audit.log. This can be helpful for keeping track of the analysis results and any potential issues identified.**

** Printed Suggestions: The code also includes print statements to provide suggestions based on the analysis. These suggestions are aimed at improving the security posture of your AWS account by highlighting potential issues or areas for improvement.**

### output will look like.

```
High Importance Functions and their outputs:
╒═══════════════════════════╤═══════════════════════════════════════════════════════════════════════════════════════════════════
│ Function Name              │ Function Output                                                                                 │
│---------------------------┼--------------------------------------------------------------------------------------------------│
│ enforce_least_privilege   │ Suggestion: Policy 'ExamplePolicy' allows excessive permissions.                                 │  
│                           │ Suggestion: Review the policy 'ExamplePolicy' for least privilege and restrict permissions       │
│                           │ to the minimum required for tasks.                                                               │
│                           │ Suggestion: Policy 'AnotherPolicy' follows least privilege principles.                           │
│                           │                                                                                                  │
│ enforce_password_policy  │ Suggestion: Consider enforcing a password policy that requires users to change their              │
│                           │ passwords periodically and sets a minimum password length.                                       │
╘═══════════════════════════╧══════════════════════════════════════════════════════════════════════════════════════════════════
```

```
Medium Importance Functions and their outputs:
╒══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
│ Function Name                            │ Function Output                                                                                  │
│-----------------------------------------┼---------------------------------------------------------------------------------------------------│
│ simulate_iam_policy                     │ Suggestion: Perform IAM policy simulation regularly to identify potential denial scenarios        │
│                                         │ and adjust policies accordingly.                                                                  │
│                                         │                                                                                                   │
│ analyze_iam_credential_report           │ Suggestion: Analyze IAM credential report regularly to identify security risks such as            │
│                                         │ unused credentials and take appropriate actions.                                                  │
│                                         │                                                                                                   │
│ review_iam_cross_account_access         │ Suggestion: Review policies attached to IAM role 'RoleName' to ensure cross-account access        │
│                                         │ is limited to trusted entities.                                                                   │
│                                         │                                                                                                   │
│ review_iam_access_keys_rotation         │ Suggestion: IAM user 'UserName' access key 'KeyId' rotation is needed to minimize unauthorized    │
│                                         │ access.                                                                                           │
│                                         │                                                                                                   │
│ review_iam_groups_configuration         │ Suggestion: Review IAM group 'GroupName' configuration to ensure users are assigned to            │
│                                         │ appropriate groups based on their roles and responsibilities.                                     │
│                                         │                                                                                                   │
│ review_iam_roles_sensitive_permissions  │ No suggestion needed: IAM role 'RoleName' does not have sensitive permissions.                    │
│                                         │                                                                                                   │
│ review_iam_role_policies_resource_tagging │ No suggestion needed: IAM role 'RoleName' policy enforces resource tagging.                     │
│                                         │                                                                                                   │
│ review_iam_policies_unused_permissions │ Suggestion: IAM policy 'PolicyName' contains unused permissions. Remove them to reduce the         │
│                                         │ attack surface.                                                                                   │
│                                         │                                                                                                   │
│ review_iam_policy_versioning           │ No suggestion needed: IAM policy 'PolicyName' versioning is appropriately managed.                 │
│                                         │                                                                                                   │
│ review_iam_role_permission_boundaries │ No suggestion needed: IAM role 'RoleName' permission boundaries are properly configured.            │
│                                         │                                                                                                   │
│ review_iam_user_mfa_status             │ No suggestion needed: MFA is enabled for IAM user 'UserName'.                                      │
│                                         │                                                                                                   │
│ review_iam_policies_privilege_escalation │ No suggestion needed: IAM policy 'PolicyName' does not contain privilege escalation paths.       │
│                                         │                                                                                                   │
│ review_iam_role_trust_relationships   │ No suggestion needed: Trust relationships for IAM role 'RoleName' are appropriately configured.     │
│                                         │                                                                                                   │
│ review_iam_policy_conditions          │ No suggestion needed: IAM policy 'PolicyName' conditions are appropriately configured.              │
│                                         │                                                                                                   │
│ review_iam_user_permissions_change_history │ Suggestion: Unable to determine IAM user last activity.                                        │
╘═══════════════════════════════════════╧══════════════════════════════════════════════════════════════════════════════════════════════════════
```

```
Low Importance Functions and their outputs:
╒══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
│ Function Name                        │ Function Output                                                                                  │
│-------------------------------------┼---------------------------------------------------------------------------------------------------│
│ review_iam_user_console_password_use │ Suggestion: IAM user 'UserName' has not logged in using the console.                             │
│                                     │                                                                                                   │
│ review_iam_user_access_keys_last_used │ Suggestion: IAM user 'UserName' access key 'KeyId' has not been used recently.                  │
│                                     │                                                                                                   │
│ review_iam_user_password_last_used   │ Suggestion: IAM user 'UserName' has not changed their password recently.                         │
│                                     │                                                                                                   │
│ review_iam_user_unused_credentials   │ Suggestion: IAM user 'UserName' has unused credentials.                                          │
╘═════════════════════════════════════╧═══════════════════════════════════════════════════════════════════════════════════════════════════
```
