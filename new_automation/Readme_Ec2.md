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
