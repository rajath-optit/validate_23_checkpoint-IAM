# AWS Resource Manager Documentation

## Overview
The AWS Resource Manager is a comprehensive Bash script designed to manage, monitor, and enforce security policies across AWS resources, with a particular focus on EC2 instances, AMIs, EBS volumes, and VPN endpoints. It provides automated checks and remediation for security configurations, resource utilization, and compliance requirements.

## Prerequisites

### System Requirements
- Linux/Unix-based operating system
- Bash shell (version 4.0 or later)
- AWS CLI version 2.0.0 or later
- jq command-line JSON processor
- Sufficient disk space for logs and temporary files
- Network connectivity to AWS services

### AWS Requirements
- AWS credentials configured with appropriate permissions
- IAM roles/permissions:
  - EC2 full access
  - IAM read access
  - Organizations read access (if using organization mode)
  - AWS Backup read access
  - Inspector read access
  - KMS read access
  - RDS read access
  - S3 read access
  - CloudWatch Logs write access

### Required IAM Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "ec2:Monitor*",
                "ec2:ModifyInstance*",
                "iam:List*",
                "iam:Get*",
                "organizations:List*",
                "organizations:Describe*",
                "backup:List*",
                "inspector2:List*",
                "kms:List*",
                "rds:Describe*",
                "s3:List*",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

## Installation

1. Clone or download the script to your local machine:
```bash
git clone <repository-url>
cd aws-resource-manager
```

2. Make the script executable:
```bash
chmod +x aws-resource-manager.sh
```

3. Create the configuration directory:
```bash
mkdir -p ~/.aws-resource-manager
```

4. Create a configuration file (optional):
```bash
touch ~/.aws-resource-manager/aws-resource-manager.conf
```

## Configuration

### Configuration File Format
Create a configuration file at `~/.aws-resource-manager.conf` with the following parameters:

```bash
# AWS Resource Manager Configuration
RETRY_ATTEMPTS=3
RETRY_DELAY=5
PARALLEL_JOBS=5
DEBUG=false
ORGANIZATION_MODE=false
LOG_FILE="/var/log/aws-resource-manager.log"
TEMP_DIR="/tmp/aws-resource-manager"

# Thresholds
THRESHOLDS=(
    ["ami_age_days"]=90
    ["instance_age_days"]=180
    ["stopped_instance_age_days"]=30
    ["unused_resource_age_days"]=7
    ["backup_retention_days"]=30
)
```

### Configuration Parameters
- `RETRY_ATTEMPTS`: Number of retry attempts for AWS API calls
- `RETRY_DELAY`: Delay in seconds between retry attempts
- `PARALLEL_JOBS`: Number of parallel jobs to run
- `DEBUG`: Enable/disable debug logging
- `ORGANIZATION_MODE`: Enable/disable AWS Organizations support
- `LOG_FILE`: Path to log file
- `TEMP_DIR`: Directory for temporary files
- `THRESHOLDS`: Various threshold values for resource management

## Usage

### Basic Usage
```bash
./aws-resource-manager.sh [-c config_file] [-p parallel_jobs] [-d] [--org-mode] <csv_file>
```

### Command-line Options
- `-c, --config`: Specify custom configuration file path
- `-p, --parallel`: Specify number of parallel jobs
- `-d, --dry-run`: Run in dry-run mode without making changes
- `--org-mode`: Enable AWS Organizations mode
- `<csv_file>`: Input CSV file containing resources to process

### CSV File Format
```csv
resource,status
arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0,alarm
arn:aws:ec2:us-west-2:123456789012:image/ami-1234567890abcdef0,alarm
```

## Features and Functions

### AMI Management
- `process_amis`: Process all AMIs in the account
- `check_ami_encryption`: Verify AMI encryption status
- `check_ami_age`: Check AMI age against thresholds
- `check_ami_public_access`: Verify AMI access permissions

Use Cases:
- Regular security audits of AMIs
- Compliance checking for encryption requirements
- Clean up of old or unused AMIs
- Prevention of public AMI exposure

### EC2 Instance Management
- `process_instances`: Process all EC2 instances
- `ensure_detailed_monitoring`: Enable detailed monitoring
- `ensure_ebs_optimization`: Verify EBS optimization
- `ensure_iam_profile`: Check IAM profile attachment
- `ensure_instance_in_vpc`: Verify VPC placement

Use Cases:
- Security compliance audits
- Resource optimization
- Cost management
- Performance monitoring

### IAM Security
- `ensure_no_pass_role_lambda_invoke`: Prevent privilege escalation
- `ensure_no_credentials_exposure`: Protect against credential leaks
- `ensure_no_management_level_access`: Limit administrative access

Use Cases:
- Security hardening
- Compliance requirements
- Access control management
- Privilege boundary enforcement

### Network Security
- `ensure_no_public_ip_address`: Prevent public IP exposure
- `ensure_no_multiple_enis`: Control network interface usage
- `ensure_unused_enis_removed`: Clean up unused resources

Use Cases:
- Network security enforcement
- Resource cleanup
- Cost optimization
- Compliance with security policies

## Advantages

1. Security Enhancement
   - Automated security checks
   - Consistent policy enforcement
   - Regular compliance monitoring
   - Reduced human error

2. Cost Optimization
   - Identification of unused resources
   - Automated cleanup processes
   - Resource lifecycle management
   - Efficient resource utilization

3. Operational Efficiency
   - Automated management tasks
   - Parallel processing capability
   - Consistent configuration management
   - Reduced manual intervention

4. Compliance Management
   - Regular compliance checks
   - Automated reporting
   - Policy enforcement
   - Audit trail maintenance

## Disadvantages

1. Operational Risks
   - Potential for unintended changes
   - Resource access requirements
   - Network dependency
   - System resource usage

2. Implementation Complexity
   - Initial setup requirements
   - Configuration management
   - Permission management
   - Learning curve

3. Resource Requirements
   - System resources
   - Network bandwidth
   - Storage space
   - Processing time

4. Maintenance Overhead
   - Regular updates needed
   - Configuration management
   - Log management
   - Performance tuning

## Use Cases

### Security Compliance
```bash
# Run security compliance check across all resources
./aws-resource-manager.sh -c security-config.conf resources.csv
```

### Cost Optimization
```bash
# Check for unused resources and cleanup
./aws-resource-manager.sh --dry-run resources.csv
```

### Multi-Account Management
```bash
# Process resources across AWS Organization
./aws-resource-manager.sh --org-mode -p 10 resources.csv
```

### Regular Maintenance
```bash
# Schedule regular maintenance checks
0 0 * * * /path/to/aws-resource-manager.sh -c /path/to/config maintenance.csv
```

## Best Practices

1. Security
   - Use least privilege permissions
   - Enable dry-run mode first
   - Monitor script execution
   - Review logs regularly

2. Performance
   - Adjust parallel jobs based on system capacity
   - Use appropriate retry settings
   - Monitor resource usage
   - Optimize CSV file size

3. Maintenance
   - Regular script updates
   - Configuration review
   - Log rotation
   - Backup configuration

4. Operation
   - Test in non-production first
   - Use meaningful resource tags
   - Document custom configurations
   - Maintain change records

## Troubleshooting

### Common Issues

1. Permission Errors
```
ERROR: Unable to access AWS Organizations
Solution: Verify IAM permissions and roles
```

2. Configuration Issues
```
ERROR: Required configuration variable not set
Solution: Check configuration file and parameters
```

3. Resource Access
```
ERROR: Failed to describe EC2 instances
Solution: Verify network connectivity and AWS credentials
```

### Debug Mode
Enable debug mode for detailed logging:
```bash
DEBUG=true ./aws-resource-manager.sh resources.csv
```

## Support and Maintenance

### Log Management
- Regular log rotation
- Log analysis for patterns
- Error tracking
- Performance monitoring

### Updates and Patches
- Regular script updates
- Security patches
- Feature enhancements
- Bug fixes

### Backup and Recovery
- Configuration backups
- Log backups
- Recovery procedures
- Rollback plans

## Additional Considerations

### Scaling
- Adjust parallel processing
- Resource throttling
- API rate limits
- System capacity

### Monitoring
- CloudWatch integration
- Log analysis
- Performance metrics
- Alert configuration

### Documentation
- Change management
- Configuration tracking
- Usage guidelines
- Training materials

## Conclusion
The AWS Resource Manager is a powerful tool for managing AWS resources at scale, providing automated security, compliance, and optimization capabilities. While it requires careful setup and maintenance, the benefits of automated resource management and security enforcement make it valuable for organizations managing AWS infrastructure.

----------------extra:each fucntion----------------

# Each Fucntion
# AWS Security Functions Documentation

# AWS EC2 Security Management Script Documentation

## Overview
This script is a comprehensive AWS EC2 security management tool that implements various security best practices and compliance checks for EC2 instances and related resources.

## Key Components

### 1. AMI Management (`handle_ami`)
**Purpose**: Manages Amazon Machine Image (AMI) security settings
- Ensures encryption is enabled
- Verifies AMI age (< 90 days)
- Restricts public access

**Changes Made**:
- Encrypts unencrypted AMIs
- Modifies AMI permissions to restrict public access
- Flags old AMIs for review

**Advantages**:
- Enhanced data security through encryption
- Reduced attack surface by limiting public access
- Better compliance through age management

**Disadvantages**:
- May increase storage costs due to encryption
- Could impact deployment speed
- Might break existing workflows dependent on public AMIs

### 2. EBS Volume Management (`handle_ebs_volume`)
**Purpose**: Manages EBS volume security settings
- Ensures encryption is enabled
- Sets DeleteOnTermination flag

**Changes Made**:
- Enables encryption for unencrypted volumes
- Modifies volume attributes for automatic deletion

**Advantages**:
- Prevents data leakage
- Reduces orphaned resource costs
- Improves compliance

**Disadvantages**:
- May impact performance slightly
- Could affect backup procedures
- Might increase operational costs

### 3. EC2 Instance Management (`handle_ec2_instance`)
**Purpose**: Implements security best practices for EC2 instances
- Enables detailed monitoring
- Configures EBS optimization
- Manages IAM profiles
- Ensures VPC placement
- Removes key pair dependencies

**Changes Made**:
- Enables CloudWatch detailed monitoring
- Activates EBS optimization
- Attaches IAM profiles
- Modifies instance attributes
- Removes key pairs

**Advantages**:
- Better visibility into instance behavior
- Improved performance with EBS
- Enhanced security through IAM roles
- Better network isolation

**Disadvantages**:
- Increased monitoring costs
- Higher instance costs for EBS optimization
- Potential disruption during modifications

### 4. IAM Role Security Checks
**Purpose**: Prevents privilege escalation and unauthorized access
- Checks for dangerous permissions
- Prevents credential exposure
- Limits resource modification capabilities

**Changes Made**:
- None (Read-only checks)
- Raises alerts for non-compliant configurations

**Advantages**:
- Prevents security misconfigurations
- Helps maintain least-privilege principle
- Identifies potential vulnerabilities

**Disadvantages**:
- May generate false positives
- Could require extensive IAM policy modifications
- Might impact legitimate administrative tasks

## Required IAM Permissions

### Read Permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "iam:GetRole",
                "iam:ListRolePolicies",
                "iam:ListAttachedRolePolicies",
                "backup:ListBackupPlans",
                "inspector2:ListFindings"
            ],
            "Resource": "*"
        }
    ]
}
```

### Write Permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:ModifyImageAttribute",
                "ec2:ModifyInstanceAttribute",
                "ec2:MonitorInstances",
                "ec2:AssociateIamInstanceProfile",
                "ec2:ModifyVolumeAttribute",
                "iam:PutRolePolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

## Implementation Steps

1. **Preparation**:
   - Configure AWS CLI
   - Set up required IAM roles
   - Test script in non-production environment

2. **Execution**:
   ```bash
   # Make script executable
   chmod +x script.sh
   
   # Run with AWS profile
   ./script.sh --profile your-aws-profile
   ```

3. **Monitoring**:
   - Check CloudWatch Logs for script execution
   - Review error messages
   - Monitor resource modifications

## Best Practices

1. Always run in test environment first
2. Enable logging for audit trails
3. Schedule regular runs
4. Review and update policies regularly
5. Monitor costs after implementation
6. Maintain backup procedures
7. Document all modifications

## Risk Mitigation

1. Create resource backups before modifications
2. Implement gradual rollout
3. Maintain rollback procedures
4. Monitor system performance
5. Keep audit logs
6. Test restoration procedures

## Additional Considerations

1. **Cost Impact**:
   - Increased CloudWatch costs
   - Higher storage costs for encryption
   - Additional backup storage costs

2. **Performance Impact**:
   - Encryption overhead
   - Monitoring overhead
   - Additional API calls

3. **Operational Impact**:
   - Changed deployment procedures
   - Modified backup processes
   - Updated security procedures

4. **Compliance Benefits**:
   - Enhanced security posture
   - Better audit capabilities
   - Improved risk management
---------> ---------> --------->
## AMI Management Functions

### handle_ami(ami_arn)
- Main handler for AMI resources
- Takes AMI ARN as input and manages encryption, age checks, and access restrictions
- Coordinates calls to AMI-specific security functions

### ensure_ami_encryption(ami_id)
- Checks if AMI is encrypted
- Encrypts unencrypted AMIs automatically
- Modifies image attributes to restrict access to account

### ensure_ami_age(ami_id)
- Verifies AMI age is not older than 90 days
- Issues warning if AMI exceeds age limit
- Suggests deprecation for old AMIs

### ensure_ami_public_access_restricted(ami_id)
- Checks if AMI is publicly accessible
- Makes public AMIs private automatically
- Removes all public launch permissions

## EBS Volume Management

### handle_ebs_volume(volume_arn)
- Main handler for EBS volumes
- Manages encryption settings
- Ensures proper deletion settings

## EC2 Instance Management

### handle_ec2_instance(instance_arn)
- Primary EC2 instance handler
- Coordinates multiple security checks
- Manages monitoring, optimization, and security settings

### ensure_detailed_monitoring(instance_id)
- Enables detailed CloudWatch monitoring
- Verifies monitoring status
- Automatically enables if disabled

### ensure_ebs_optimization(instance_id)
- Checks EBS optimization status
- Enables optimization if disabled
- Improves storage performance

### ensure_iam_profile(instance_id)
- Verifies IAM profile attachment
- Attaches default profile if missing
- Ensures proper instance permissions

### ensure_instance_in_vpc(instance_id)
- Validates instance VPC placement
- Reports error if instance is not in VPC
- Ensures network isolation

### ensure_no_key_pairs(instance_id)
- Removes SSH key pairs
- Disables API termination
- Enhances instance security

## VPN Endpoint Management

### handle_vpn_endpoint(vpn_arn)
- Manages Client VPN endpoints
- Controls connection logging
- Ensures security compliance

### ensure_vpn_connection_logging(vpn_id)
- Enables client connection logging
- Configures CloudWatch log groups
- Tracks VPN access

## Security Compliance Functions

### ensure_no_inspector_findings(instance_id)
- Checks AWS Inspector results
- Identifies high-severity findings
- Reports security vulnerabilities

### ensure_no_pass_role_lambda_invoke(instance_id)
- Restricts IAM role permissions
- Prevents pass role access
- Limits Lambda function invocation

### ensure_no_credentials_exposure(instance_id)
- Prevents credential exposure
- Checks IAM role policies
- Removes risky permissions

### ensure_no_s3_permissions_alteration(instance_id)
- Restricts S3 permission changes
- Protects critical configurations
- Prevents unauthorized modifications

### ensure_no_cloud_log_tampering(instance_id)
- Prevents log manipulation
- Protects audit trails
- Maintains logging integrity

### ensure_no_data_destruction_access(instance_id)
- Prevents destructive actions
- Protects against data loss
- Limits deletion permissions

### ensure_no_db_management_write_access(instance_id)
- Restricts database modifications
- Limits write access
- Protects database integrity

### ensure_no_defense_evasion_access(instance_id)
- Prevents security bypass
- Maintains defense mechanisms
- Blocks evasion attempts

### ensure_no_kms_destruction_access(instance_id)
- Protects KMS resources
- Prevents key deletion
- Maintains encryption infrastructure

### ensure_no_rds_destruction_access(instance_id)
- Protects RDS resources
- Prevents database deletion
- Maintains database availability

### ensure_no_eip_hijacking_access(instance_id)
- Prevents IP address hijacking
- Protects Elastic IPs
- Maintains network security

### ensure_no_management_level_access(instance_id)
- Restricts administrative access
- Limits management permissions
- Enforces least privilege

### ensure_no_group_creation_with_policy(instance_id)
- Prevents unauthorized group creation
- Restricts policy attachments
- Controls IAM group management

### ensure_no_role_creation_with_policy(instance_id)
- Prevents unauthorized role creation
- Restricts policy attachments
- Controls IAM role management

### ensure_no_user_creation_with_policy(instance_id)
- Prevents unauthorized user creation
- Restricts policy attachments
- Controls IAM user management

### ensure_no_org_write_access(instance_id)
- Restricts organization changes
- Protects organizational structure
- Limits administrative access

### ensure_no_privilege_escalation_access(instance_id)
- Prevents privilege escalation
- Maintains security boundaries
- Limits permission expansion

### ensure_no_sg_write_access(instance_id)
- Restricts security group changes
- Protects network security
- Maintains firewall rules

### ensure_no_resource_policy_write_access(instance_id)
- Controls resource policy modifications
- Protects resource configurations
- Maintains access controls

### ensure_no_s3_critical_config_write(instance_id)
- Protects S3 configurations
- Prevents critical changes
- Maintains bucket security

### ensure_no_write_level_access(instance_id)
- Restricts write permissions
- Enforces read-only access
- Prevents unauthorized changes

## Instance Configuration Management

### ensure_no_launch_wizard_security_groups(instance_id)
- Removes default security groups
- Enforces custom security groups
- Improves security posture

### ensure_instance_not_older_than_180_days(instance_id)
- Checks instance age
- Flags old instances
- Promotes instance refresh

### ensure_no_public_ip_address(instance_id)
- Removes public IP addresses
- Enforces private networking
- Improves security

### ensure_no_multiple_enis(instance_id)
- Limits network interfaces
- Simplifies network architecture
- Reduces attack surface

### ensure_backup_plan_protection(instance_id)
- Verifies backup coverage
- Ensures data protection
- Maintains business continuity

### ensure_public_ec2_iam_profile(instance_id)
- Checks public instance IAM profiles
- Enforces proper permissions
- Enhances security

### ensure_termination_protection_enabled(instance_id)
- Enables termination protection
- Prevents accidental deletion
- Protects critical instances

### ensure_no_secrets_in_user_data(instance_id)
- Scans user data for secrets
- Prevents credential exposure
- Maintains security hygiene

### ensure_imdsv2_enabled(instance_id)
- Enforces IMDSv2 usage
- Improves metadata security
- Prevents SSRF attacks

### ensure_no_paravirtual_instances(instance_id)
- Checks virtualization type
- Prevents legacy instance types
- Maintains modern infrastructure

## Launch Template Management

### ensure_no_public_ip_in_launch_template(launch_template_id)
- Prevents public IP assignment
- Enforces private networking
- Maintains security in templates

## Network Interface Management

### ensure_unused_enis_removed()
- Identifies unused ENIs
- Promotes cleanup
- Reduces costs

## Instance Lifecycle Management

### ensure_stopped_instances_removed_30_days()
- Identifies stopped instances
- Promotes resource cleanup
- Maintains cost efficiency

### ensure_stopped_instances_removed_90_days()
- Identifies long-term stopped instances
- Enforces instance cleanup
- Reduces unused resources

## Transit Gateway Management

### ensure_auto_accept_shared_attachments_disabled()
- Controls attachment acceptance
- Prevents unauthorized connections
- Maintains network security

----------more detailed_each fucntion----------
# AWS EC2 Security Compliance Checks Documentation

## AMI Security Checks

### 1. AMI Encryption Check
**Function**: `ensure_ami_encryption`
**Purpose**: Ensures Amazon Machine Images (AMIs) are encrypted
**Changes Made**: 
- Modifies AMI attributes to enable encryption
- Adds launch permissions for account ID
**Impact**: Enhanced data security at rest
**Advantages**:
- Prevents data exposure if AMI is shared/leaked
- Complies with data protection regulations
**Disadvantages**:
- Slightly increased storage costs
- Minor performance impact during instance launch

### 2. AMI Age Verification
**Function**: `ensure_ami_age`
**Purpose**: Flags AMIs older than 90 days
**Changes Made**: None (monitoring only)
**Advantages**:
- Ensures use of current, patched images
- Reduces security vulnerabilities
**Disadvantages**:
- May require frequent AMI updates
- Could impact existing deployment processes

### 3. AMI Public Access Restriction
**Function**: `ensure_ami_public_access_restricted`
**Changes Made**: 
- Removes public access permissions
- Makes AMI private
**Impact**: Prevents unauthorized AMI access
**Advantages**:
- Prevents accidental exposure
- Controls AMI distribution
**Disadvantages**:
- Requires explicit sharing for collaboration
- Additional overhead in AMI sharing management

## EC2 Instance Configuration

### 4. Detailed Monitoring
**Function**: `ensure_detailed_monitoring`
**Changes Made**: 
- Enables detailed CloudWatch monitoring
**Impact**: 1-minute metric intervals
**Advantages**:
- Better visibility into instance performance
- Faster anomaly detection
**Disadvantages**:
- Additional CloudWatch costs
- Increased metric storage

### 5. EBS Optimization
**Function**: `ensure_ebs_optimization`
**Changes Made**: 
- Enables EBS optimization flag
**Impact**: Dedicated bandwidth for EBS
**Advantages**:
- Improved storage performance
- Consistent I/O operations
**Disadvantages**:
- May not be available on all instance types
- Additional instance costs

### 6. IAM Profile Management
**Function**: `ensure_iam_profile`
**Changes Made**: 
- Attaches IAM instance profile
**Impact**: Enables AWS service access
**Advantages**:
- Secure AWS service access
- No hard-coded credentials
**Disadvantages**:
- Requires IAM role management
- Potential permission escalation if misconfigured

### 7. VPC Requirement
**Function**: `ensure_instance_in_vpc`
**Changes Made**: None (verification only)
**Impact**: Ensures network isolation
**Advantages**:
- Network isolation
- Security group control
**Disadvantages**:
- VPC design complexity
- Potential routing overhead

## IAM Role Security

### 8. Pass Role and Lambda Access
**Function**: `ensure_no_pass_role_lambda_invoke`
**Changes Made**: None (verification only)
**Impact**: Prevents privilege escalation
**Advantages**:
- Prevents unauthorized role assumption
- Limits Lambda function access
**Disadvantages**:
- May restrict legitimate automation
- Requires careful permission planning

[Documentation continues with detailed explanations for each security check...]

## Best Practices Implementation

### Instance Lifecycle Management

1. **Termination Protection**
**Function**: `ensure_termination_protection_enabled`
**Changes Made**: 
- Enables termination protection
**Impact**: Prevents accidental instance deletion
**Advantages**:
- Prevents accidental termination
- Protects critical instances
**Disadvantages**:
- Additional step when intentional termination needed
- May complicate automation scripts

### Network Security

1. **Public IP Restrictions**
**Function**: `ensure_no_public_ip_address`
**Changes Made**: None (verification only)
**Impact**: Ensures private network usage
**Advantages**:
- Reduces attack surface
- Better network security
**Disadvantages**:
- Requires bastion/VPN for access
- More complex network architecture

[Documentation continues with remaining security checks...]

## Usage Guidelines

1. Review changes before implementation
2. Test in non-production environment first
3. Monitor for unintended impacts
4. Maintain backup procedures
5. Document exceptions and approvals

## Implementation Risks

1. Service interruption if misconfigured
2. Potential access issues
3. Application compatibility impacts
4. Performance impacts
5. Cost implications

## Prerequisites

1. AWS CLI configured
2. Appropriate IAM permissions
3. Backup procedures in place
4. Change management process
5. Testing environment available
---------------------------------

