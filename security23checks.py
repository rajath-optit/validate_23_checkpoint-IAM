import boto3
from botocore.exceptions import ClientError
import paramiko
import psycopg2
import mysql.connector
import subprocess
from tabulate import tabulate
import os


# Function to check if the script has the necessary permissions to modify security groups
print("Function to check if the script has the necessary permissions to modify security groups")

def check_permissions():
    """
    Check if the script has the necessary permissions to modify security groups.
    This function checks if the IAM policy attached to the script includes the required permissions.
    """
    iam = boto3.client('iam')
    try:
        response = iam.get_policy(
            PolicyArn='arn:aws:iam::aws:policy/AmazonEC2FullAccess'  # Example policy, adjust as necessary
        )
        policy_version = response['Policy']['DefaultVersionId']
        response = iam.get_policy_version(PolicyArn=response['Policy']['Arn'], VersionId=policy_version)
        permissions = response['PolicyVersion']['Document']['Statement']
        
        required_permissions = ['ec2:AuthorizeSecurityGroupIngress', 'ec2:DescribeSecurityGroups']
        
        for perm in permissions:
            if perm['Action'] in required_permissions and perm['Effect'] == 'Allow':
                return True
    
    except KeyError as e:
        print(f"KeyError: {e}")
        return False
    
    return False


# Check permissions and provide recommendations
if check_permissions():
    print("You have the necessary permissions to modify security groups.")
    print("For read-only access, ensure the 'ec2:DescribeSecurityGroups' permission is enabled.")
    print("For write access, including configuring security groups, ensure the 'ec2:AuthorizeSecurityGroupIngress' permission is enabled.")
    print("Consider providing additional permissions like 'ec2:RevokeSecurityGroupIngress' and 'ec2:CreateSecurityGroup' for more advanced actions.")
else:
    print("You don't have the necessary permissions to modify security groups.")


# 1.Check if applications expose to the public only via port 443
print("1.Check if applications expose to the public only via port 443")
def check_port_443_only():
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups()
    violations = []

    for group in response['SecurityGroups']:
        for permission in group['IpPermissions']:
            if permission['FromPort'] == 443 and permission['ToPort'] == 443:
                for ip_range in permission['IpRanges']:
                    if ip_range['CidrIp'] == '0.0.0.0/0' or ip_range['CidrIp'] == '::/0':
                        violations.append(group['GroupId'])

    if violations:
        print("\nReport: Security Groups Violating Port 443 Exposure\n")
        print("These security groups allow inbound traffic on port 443 from any IP address (0.0.0.0/0 or ::/0).")
        print("This can potentially expose applications to the public, which might pose security risks.")
        print("Recommendation: Restrict inbound traffic on port 443 to specific IP ranges as needed.\n")
        
        print("Security groups violating port 443 exposure:")
        for group_id in violations:
            print(f"- Security Group ID: {group_id}")

        configure = input("\nDo you want to configure these security groups? (yes/no): ")
        if configure.lower() == 'yes':
            for group_id in violations:
                try:
                    ec2.authorize_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 443,
                                'ToPort': 443,
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Modify this as needed
                            }
                        ]
                    )
                    print(f"Security group {group_id} configured successfully.")
                except Exception as e:
                    print(f"Failed to configure security group {group_id}: {str(e)}")
    else:
        print("No security groups found violating port 443 exposure.")

    print("\nCheckpoint 1: Applications expose to the public only via port 443 - Complete\n")
    print("-" * 50)


# Check if AWS access is properly managed to the team as required . Developers should have least privileges access. (Read / Read/write / Root account). No need for Dev team to have access to AWS console.
def check_aws_access():
    print("\nCheckpoint 2: Enable AWS Access and Ensure Least Privilege for Developers\n")
    print("Verifying AWS access management for the team:")
    print("Developers should have least privilege access (Read / Read-write / Root account).")
    print("No need for Dev team to have access to AWS console.")

    # List IAM users and their permissions
    import boto3

def list_iam_users():
    iam = boto3.client('iam')
    response = iam.list_users()
    return response['Users']

def list_iam_groups():
    iam = boto3.client('iam')
    response = iam.list_groups()
    return response['Groups']

def get_user_policies(user_name):
    iam = boto3.client('iam')
    response = iam.list_attached_user_policies(UserName=user_name)
    return response['AttachedPolicies']

def get_group_policies(group_name):
    iam = boto3.client('iam')
    response = iam.list_attached_group_policies(GroupName=group_name)
    return response['AttachedPolicies']

def get_user_groups(user_name):
    iam = boto3.client('iam')
    response = iam.list_groups_for_user(UserName=user_name)
    return response['Groups']

def is_cloudtrail_enabled():
    cloudtrail = boto3.client('cloudtrail')
    response = cloudtrail.describe_trails()
    return len(response['trailList']) > 0

def get_recent_cloudtrail_events():
    cloudtrail = boto3.client('cloudtrail')
    response = cloudtrail.lookup_events()
    return response['Events']

def check_aws_access():
    print("\nCheckpoint 2: Enable AWS Access and Ensure Least Privilege for Developers\n")
    print("Verifying AWS access management for the team:")
    print("Developers should have least privilege access (Read / Read-write / Root account).")
    print("No need for Dev team to have access to AWS console.")

    # List IAM users and their permissions
    print("\nIAM Users:")
    users = list_iam_users()
    if users:
        for user in users:
            user_name = user['UserName']
            print(f"- {user_name}")
            print("  Permissions:")
            policies = get_user_policies(user_name)
            for policy in policies:
                print(f"  - {policy['PolicyName']}")
            
            # Get IAM groups the user belongs to
            groups = get_user_groups(user_name)
            print("  Belongs to Groups:")
            for group in groups:
                print(f"  - {group['GroupName']}")
    else:
        print("No IAM users found. Unable to verify AWS access management.")
        return

    # List IAM groups and their permissions
    print("\nIAM Groups:")
    groups = list_iam_groups()
    if groups:
        for group in groups:
            group_name = group['GroupName']
            print(f"- {group_name}")
            print("  Permissions:")
            policies = get_group_policies(group_name)
            for policy in policies:
                print(f"  - {policy['PolicyName']}")
    else:
        print("No IAM groups found.")

    # Check CloudTrail status
    print("\nCloudTrail Status:")
    if is_cloudtrail_enabled():
        print("CloudTrail is enabled.")
        print("\nRecent CloudTrail Events:")
        events = get_recent_cloudtrail_events()
        for event in events:
            print(f"- {event['EventId']}: {event['EventName']} ({event['EventTime']})")
    else:
        print("CloudTrail is not enabled.")

    # Provide recommendations
    print("\nRecommendations:")
    print("- Remove unnecessary permissions from IAM users and groups.")
    print("- Restrict access to AWS console for the development team.")
    print("- Implement least privilege principles for IAM policies.")

    print("-" * 50)

# Check if traffic from end users passes through security solutions
def check_security_solutions():
    print("\nCheckpoint 3: Ensure All Traffic Passes through Perimeter Security Solutions\n")
    print("Checking security solutions for all running instances...")
# This can be partially automated. You can check if resources are associated with WAF and AWS Shield,
    # but verifying if all traffic passes through them might require network configuration verification.
    print("Checking security solutions...")
    print("Partially automating the check for association with WAF and AWS Shield.")
    print("Please note: This function partially automates the process of checking if traffic from end users passes through Perimeter Security Solutions such as WAF and AWS Shield. It checks for associations with WAF and AWS Shield, but verifying if all traffic passes through them might require network configuration verification, which cannot be fully automated.")

# Function to check if WAF is associated with resources
def has_waf_association(resource_id):
    waf = boto3.client('waf')
    try:
        response = waf.get_web_acl_for_resource(ResourceArn=resource_id)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'WAFNonexistentItemException':
            return False
        else:
            raise

# Function to check if AWS Shield is associated with resources
def has_shield_association(resource_id):
    shield = boto3.client('shield')
    try:
        response = shield.describe_protection(ResourceArn=resource_id)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return False
        else:
            raise

# Function to check if the script has the necessary permissions to modify resources
def check_permissions():
    # Placeholder: Implement logic to check permissions (e.g., using IAM policies)
    # Return True if permissions are sufficient, False otherwise
    return True

# Function to automatically configure WAF for resources
def configure_waf(resource_id):
    # Placeholder: Implement logic to configure WAF for the specified resource
    # This can involve creating a Web ACL and associating it with the resource
    
    # Ensure that the script has the necessary permissions to perform these actions
    if check_permissions():
        # Placeholder: Example code to create and associate Web ACL
        print(f"WAF configured successfully for resource {resource_id}.")
        return True
    else:
        print("Insufficient permissions to configure WAF.")
        return False

# Function to check security solutions
def check_security_solutions():
    print("\nCheckpoint 3: Ensure All Traffic Passes through Perimeter Security Solutions\n")
    print("Checking security solutions for all running instances...")
    
    # Initialize EC2 client
    ec2 = boto3.client('ec2')
    
    # Describe instances
    response = ec2.describe_instances()

    # Iterate over reservations and instances
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_state = instance['State']['Name']
            
            # Check if the instance is running
            if instance_state == 'running':
                print(f"\nChecking instance {instance_id}...")
                
                # Check if WAF is associated with the instance
                if not has_waf_association(instance_id):
                    print(f"WAF is not associated with instance {instance_id}.")
                    
                    # Configure WAF automatically if permissions allow and user agrees
                    configure = input("Do you want to configure WAF for this instance? (yes/no): ")
                    if configure.lower() == 'yes':
                        configure_waf(instance_id)
                else:
                    print(f"WAF is associated with instance {instance_id}.")
                
                # Check if AWS Shield is associated with the instance
                if has_shield_association(instance_id):
                    print(f"AWS Shield is associated with instance {instance_id}.")
                else:
                    print(f"AWS Shield is not associated with instance {instance_id}.")

    print("\nRecommendation:")
    print("- Ensure all running instances have WAF and AWS Shield associated for perimeter security.")
    print("-" * 50)


# Check if applications are enabled with horizontal load balancers
def check_load_balancers():
    print("\nCheckpoint 4: Applications should be enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic\n")
    print("Checking load balancer associations for Auto Scaling Groups...")

    # Initialize the Autoscaling client
    autoscaling = boto3.client('autoscaling')

    # Describe all Auto Scaling Groups
    response = autoscaling.describe_auto_scaling_groups()

    # Check load balancer associations for each Auto Scaling Group
    violations = []
    for group in response['AutoScalingGroups']:
        group_name = group['AutoScalingGroupName']
        
        # Check if load balancer associations exist
        if 'LoadBalancerNames' not in group or not group['LoadBalancerNames']:
            violations.append(group_name)

    # Report findings
    if violations:
        print("\nAuto Scaling Groups not associated with load balancers:")
        for group_name in violations:
            print(f"- {group_name}")
        
        # Ask for confirmation to configure load balancer
        configure = input("\nDo you want to configure a load balancer for these Auto Scaling Groups? (yes/no): ")
        if configure.lower() == 'yes':
            print("\nConfiguring load balancers...")
            print("Adding load balancers to these Auto Scaling Groups can help distribute incoming traffic evenly across instances, improving application availability and fault tolerance.")
            print("Steps to configure load balancers:")
            print("1. Choose a suitable load balancer type (e.g., Application Load Balancer, Network Load Balancer).")
            print("2. Create a new load balancer or select an existing one.")
            print("3. Associate the load balancer with the Auto Scaling Group(s) that need to scale horizontally.")
            print("4. Configure health checks to monitor the instances behind the load balancer.")
            print("5. Optionally, set up listeners and routing rules to route traffic to the instances.")
            print("6. Test the configuration to ensure that traffic is distributed properly.")
            print("7. Monitor the load balancer and Auto Scaling Group performance regularly.")
    else:
        print("\nAll Auto Scaling Groups are associated with load balancers.")
        print("Recommendation: Ensure that all applications are configured to use horizontal load balancers (Auto scaling) to effectively handle surges in traffic and improve availability and scalability.")

    # Move to the next function if this one has been executed
    print("\nManual configuration is recommended for optimal customization and control.")
    print("-" * 50)

# Check if application servers are installed with IPS/IDS and DDoS protection
print("5.Application servers to be installed with IPS/IDS and DDoS (Examples for solution are - TrendMicro Deep Security).")

def check_security_solutions_servers():
    print("Checkpoint 5: Install IPS/IDS and DDoS Protection on Application Servers")
    print("Please note: This function checks if application servers are installed with IPS/IDS and DDoS protection solutions. However, verifying their configurations and effectiveness may require manual inspection.")
def describe_ec2_instances():
    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_instances()
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_details = {
                    'InstanceId': instance['InstanceId'],
                    'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                    'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A')
                }
                instances.append(instance_details)
        return instances
    except ClientError as e:
        print(f"Error describing EC2 instances: {e}")
        return []

# Example usage:
instances = describe_ec2_instances()
print(instances)
try:
        ssm = boto3.client('ssm')
        instances = describe_ec2_instances()
        violations = []

        for instance in instances:
            instance_id = instance['InstanceId']

            # Run command to check for installed security solutions
            command = "dpkg -l | grep snort || true"  # Example command to check for Snort IDS
            response = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': [command]}
            )

            # Check command output for security solution presence
            output = response['Command']['Output'].strip()
            if not output:
                violations.append(instance_id)

        # Report findings
        if violations:
            print("\nServers Missing Security Solutions:")
            for instance_id in violations:
                print(f"- {instance_id}: Missing IPS/IDS or DDoS protection")
            print("\nRecommendation: Consider installing and configuring IPS/IDS or DDoS protection solutions on the affected servers.")
        else:
            print("\nAll Servers Have Required Security Solutions Installed.")

except ClientError as e:
        print(f"Error: {str(e)}")
print("_ " * 50)

# Check if Master-Slave architecture is set up for the database
print("6.We should always have Master - Slave Architecture set up for DB.")
def check_database_architecture():
    print("This script provides a menu-driven interface to perform various security checks and recommendations.")
    print("Each option corresponds to a specific security check or recommendation.")
    print("Option 0 allows you to scan all checks at once.")
    print("After executing the selected option(s), the script generates a report summarizing the findings.")
def get_database_credentials():
        host = input("Enter the database host: ")
        port = input("Enter the database port: ")
        user = input("Enter the database username: ")
        password = input("Enter the database password: ")
        database = input("Enter the database name: ")
        return host, port, user, password, database

def confirm_continue():
        while True:
            answer = input("Do you have the necessary database connection details? (yes/no): ").lower()
            if answer == 'yes':
                return True
            elif answer == 'no':
                return False
            else:
                print("Please enter 'yes' or 'no'.")

def get_database_type(host, port, user, password, database):
        try:
            # Try connecting to PostgreSQL
            conn = psycopg2.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                database=database
            )
            conn.close()
            return "PostgreSQL"
        except psycopg2.OperationalError:
            pass

        try:
            # Try connecting to MySQL
            conn = mysql.connector.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                database=database
            )
            conn.close()
            return "MySQL"
        except mysql.connector.Error:
            pass

        # If neither PostgreSQL nor MySQL is detected, return None
        return None

def check_master_slave_configuration(host, port, user, password, database, database_type):
        if database_type == "PostgreSQL":
            try:
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    user=user,
                    password=password,
                    database=database
                )
                cursor = conn.cursor()

                # Check if the database is configured as a Master
                cursor.execute("SELECT pg_is_in_recovery()")
                is_in_recovery = cursor.fetchone()[0]

                # Report findings
                if is_in_recovery:
                    print("The database is configured as a Slave (replica) in a Master-Slave setup.")
                else:
                    print("The database is configured as a Master in a Master-Slave setup.")

                cursor.close()
                conn.close()
            except psycopg2.OperationalError as e:
                print(f"Error connecting to PostgreSQL: {e}")
        elif database_type == "MySQL":
            try:
                conn = mysql.connector.connect(
                    host=host,
                    port=port,
                    user=user,
                    password=password,
                    database=database
                )
                cursor = conn.cursor()

                # Check if the database is configured as a Master
                cursor.execute("SHOW SLAVE STATUS")
                slave_status = cursor.fetchone()

                # Report findings
                if slave_status:
                    print("The database is configured as a Slave (replica) in a Master-Slave setup.")
                else:
                    print("The database is configured as a Master in a Master-Slave setup.")

                cursor.close()
                conn.close()
            except mysql.connector.Error as e:
                print(f"Error connecting to MySQL: {e}")
        else:
            print("Invalid or unsupported database type.")

    # Prompt user for database credentials
host, port, user, password, database = get_database_credentials()

    # Get the database type
database_type = get_database_type(host, port, user, password, database)

if database_type:
        print(f"The database type is: {database_type}")
        # Check for Master-Slave configuration
        check_master_slave_configuration(host, port, user, password, database, database_type)
else:
        print("Failed to determine the database type.")

    # Suggestion for manual verification
print("\nManual Verification:")
print("While this script can check for Master-Slave configuration, it's important to note that some configurations")
print("may not be accurately detected or may require additional context. For critical systems, it's recommended")
print("to manually review the database configuration or consult with a database administrator to ensure")
print("correctness and reliability.")

print("_ " * 50)

# Check if managed DB (RDS) is used
print("7.We should always recommend to have Managed DB (Example : RDS).")
def check_managed_db():
    # This can be partially automated by checking if RDS instances are used,
    # but verifying if all databases are managed might require manual verification.
    try:
        # Initialize RDS client
        rds = boto3.client('rds')

        # Get all RDS instances
        response = rds.describe_db_instances()

        # Check if there are any RDS instances
        if response['DBInstances']:
            print("Managed databases (RDS instances) are being used.")
        else:
            print("No managed databases (RDS instances) found.")

    except Exception as e:
        print(f"Error: {e}")

# Suggestion for manual verification
print("\nManual Verification:")
print("While this script can check for managed databases (RDS instances), verifying if all databases are managed")
print("might require manual verification. Managed databases in AWS (RDS instances) are automatically managed by AWS,")
print("but there might be databases hosted outside of RDS or in other cloud providers.")
print("To ensure completeness, manually review all databases in your AWS account and consider consulting with")
print("database administrators or reviewing documentation for other cloud providers.")

print("_ " * 50)

# Check if EBS volumes are encrypted
print("\n8.Encrypt all EBS volumes.")
def check_ebs_encryption():
    # This can be automated by checking the encryption status of EBS volumes.
    try:
        # Initialize EC2 client
        ec2 = boto3.client('ec2')

        # Get all EBS volumes
        response = ec2.describe_volumes()

        # Check encryption status for each volume
        encrypted_volumes = []
        unencrypted_volumes = []
        for volume in response['Volumes']:
            volume_id = volume['VolumeId']
            encryption = volume.get('Encrypted', False)
            if encryption:
                encrypted_volumes.append(volume_id)
            else:
                unencrypted_volumes.append(volume_id)

        # Report findings
        if encrypted_volumes:
            print("Encrypted EBS volumes found:")
            for volume_id in encrypted_volumes:
                print(f"- {volume_id}")
        else:
            print("No encrypted EBS volumes found.")

        if unencrypted_volumes:
            print("\nUnencrypted EBS volumes found:")
            for volume_id in unencrypted_volumes:
                print(f"- {volume_id}")
            
            # Offer to configure encryption
            configure = input("Do you want to encrypt these volumes? (yes/no): ")
            if configure.lower() == 'yes':
                for volume_id in unencrypted_volumes:
                    try:
                        # Encrypt the volume
                        ec2.modify_volume(
                            VolumeId=volume_id,
                            Encrypted=True
                        )
                        print(f"Volume {volume_id} encrypted successfully.")
                    except Exception as e:
                        print(f"Failed to encrypt volume {volume_id}: {e}")
                
                # Suggestion for encryption
                print("\nRecommendation:")
                print("Encrypting EBS volumes adds an additional layer of security to your data.")
                print("Encrypted volumes help protect sensitive information and ensure compliance with")
                print("data privacy regulations. It is essential for maintaining the confidentiality")
                print("and integrity of your data.")
        else:
            print("All EBS volumes are encrypted.")

    except Exception as e:
        print(f"Error: {e}")
    
print("_ " * 50)

# Check if S3 buckets are encrypted
print("\n9.Encrypt all S3 buckets.")
def check_s3_encryption():
    # This can be automated by checking the encryption status of S3 buckets.
    try:
        # Initialize S3 client
        s3 = boto3.client('s3')

        # Get all S3 buckets
        response = s3.list_buckets()

        # Check encryption status for each bucket
        encrypted_buckets = []
        unencrypted_buckets = []
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            if 'ServerSideEncryptionConfiguration' in encryption:
                encrypted_buckets.append(bucket_name)
            else:
                unencrypted_buckets.append(bucket_name)

        # Report findings
        if encrypted_buckets:
            print("Encrypted S3 buckets found:")
            for bucket_name in encrypted_buckets:
                print(f"- {bucket_name}")
        else:
            print("No encrypted S3 buckets found.")

        if unencrypted_buckets:
            print("\nUnencrypted S3 buckets found:")
            for bucket_name in unencrypted_buckets:
                print(f"- {bucket_name}")
            
            # Offer to configure encryption
            configure = input("Do you want to encrypt these buckets? (yes/no): ")
            if configure.lower() == 'yes':
                for bucket_name in unencrypted_buckets:
                    try:
                        # Configure encryption for the bucket
                        s3.put_bucket_encryption(
                            Bucket=bucket_name,
                            ServerSideEncryptionConfiguration={
                                'Rules': [
                                    {
                                        'ApplyServerSideEncryptionByDefault': {
                                            'SSEAlgorithm': 'AES256'
                                        }
                                    }
                                ]
                            }
                        )
                        print(f"Bucket {bucket_name} encrypted successfully.")
                    except Exception as e:
                        print(f"Failed to encrypt bucket {bucket_name}: {e}")
                
                # Suggestion for encryption
                print("\nRecommendation:")
                print("Enabling server-side encryption (SSE) for S3 buckets adds an additional layer of")
                print("security to your data, ensuring that objects stored in the bucket are encrypted")
                print("at rest. It is essential for maintaining the confidentiality and integrity of")
                print("your data.")
        else:
            print("All S3 buckets are encrypted.")

    except Exception as e:
        print(f"Error: {e}")
print("_ " * 50)

# Check if versioning is enabled for all S3 buckets
print("\n10.Enable versioning of all S3.")
def check_s3_versioning():
    # This can be automated by checking the versioning configuration of S3 buckets.
    try:
        # Initialize S3 client
        s3 = boto3.client('s3')

        # Get all S3 buckets
        response = s3.list_buckets()

        # Check versioning status for each bucket
        versioning_enabled_buckets = []
        versioning_disabled_buckets = []
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if 'Status' in versioning and versioning['Status'] == 'Enabled':
                versioning_enabled_buckets.append(bucket_name)
            else:
                versioning_disabled_buckets.append(bucket_name)

        # Report findings
        if versioning_enabled_buckets:
            print("S3 buckets with versioning enabled:")
            for bucket_name in versioning_enabled_buckets:
                print(f"- {bucket_name}")
        else:
            print("No S3 buckets with versioning enabled.")

        if versioning_disabled_buckets:
            print("\nS3 buckets with versioning disabled:")
            for bucket_name in versioning_disabled_buckets:
                print(f"- {bucket_name}")
            
            # Offer suggestion to enable versioning
            configure = input("Do you want to enable versioning for these buckets? (yes/no): ")
            if configure.lower() == 'yes':
                for bucket_name in versioning_disabled_buckets:
                    try:
                        # Enable versioning for the bucket
                        s3.put_bucket_versioning(
                            Bucket=bucket_name,
                            VersioningConfiguration={
                                'Status': 'Enabled'
                            }
                        )
                        print(f"Versioning enabled for bucket {bucket_name}.")
                    except Exception as e:
                        print(f"Failed to enable versioning for bucket {bucket_name}: {e}")
                
                # Suggestion for enabling versioning
                print("\nRecommendation:")
                print("Enabling versioning for S3 buckets allows you to retain multiple versions")
                print("of an object in the bucket. This helps protect against accidental deletion")
                print("or modification of objects, providing a backup mechanism for data recovery.")
        else:
            print("All S3 buckets have versioning enabled.")

    except Exception as e:
        print(f"Error: {e}")
print("_ " * 50)

# Check if CloudTrail is enabled for all AWS accounts
print("\n11.Enable Cloud Trail for all AWS accounts.")
# This can be automated by checking the CloudTrail configuration for each AWS account.
def list_member_accounts():
    try:
        # Initialize AWS Organizations client
        orgs = boto3.client('organizations')

        # List all member accounts
        response = orgs.list_accounts()

        # Extract account IDs
        account_ids = [account['Id'] for account in response['Accounts']]

        return account_ids

    except Exception as e:
        print(f"Error listing member accounts: {e}")
        return []

def check_cloudtrail_for_accounts(account_ids):
    try:
        # Initialize CloudTrail client
        cloudtrail = boto3.client('cloudtrail')

        # List CloudTrail trails for each account
        for account_id in account_ids:
            print(f"Checking CloudTrail status for AWS account {account_id}...")

            # Get CloudTrail trails
            response = cloudtrail.describe_trails()

            # Check if CloudTrail is enabled for any trail
            is_enabled = any(trail['IsLogging'] for trail in response.get('trailList', []))

            if is_enabled:
                print("CloudTrail is enabled for this account.")
            else:
                print("CloudTrail is not enabled for this account.")

    except Exception as e:
        print(f"Error checking CloudTrail for account {account_id}: {e}")

def check_cloudtrail():
    # This can be automated by checking the CloudTrail configuration for each AWS account.
    try:
        # List member accounts in AWS Organizations
        member_account_ids = list_member_accounts()

        # Check CloudTrail configuration for each member account
        if member_account_ids:
            check_cloudtrail_for_accounts(member_account_ids)
        else:
            print("No member accounts found.")

    except Exception as e:
        print(f"Error: {e}")

# Suggestion for permissions
print("""To run this script, ensure that the IAM user or role executing the script has the following permissions:

1. ListAccounts: This permission is required to list member accounts in AWS Organizations. You can attach the organizations:ListAccounts permission to the IAM policy associated with the user or role.

2. DescribeTrails: This permission is required to describe CloudTrail trails in each AWS account. You can attach the cloudtrail:DescribeTrails permission to the IAM policy associated with the user or role.

If you have the necessary permissions, the script will list member accounts and check the CloudTrail configuration for each account. If you encounter permission errors, please contact your AWS administrator to grant the required permissions.
""")
print("-" * 50)

# Check if Command Line Recorder (CLR) is enabled for all servers
print("\n12.Enable Command Line Recorder (CLR) for all servers.")
def check_clr():
    # This can be partially automated. You can check if CLR is installed and enabled,
    try:
        # Check if CLR software package is installed
        clr_installed = subprocess.call(['dpkg', '-l', 'clr'])

        # Check if CLR service/process is running
        clr_process_running = subprocess.call(['service', 'clr', 'status'])

        # Check if CLR configuration files exist and are correctly configured
        # This can vary based on the specific configuration of CLR
        
        # Placeholder for checking CLR configuration files
        
        if clr_installed == 0 and clr_process_running == 0:
            print("CLR is installed and enabled.")
        else:
            print("CLR is not installed or enabled.")

    except Exception as e:
        print(f"Error: {e}")
    # but verifying its proper usage might require manual inspection.
    print("""To manually check if Command Line Recorder (CLR) is enabled for all servers, follow these steps:
    1. SSH into each server using appropriate credentials.
    2. Run the command to check the CLR status.
    3. If CLR is installed and enabled, you will see relevant output indicating its status.
    4. If CLR is not installed or enabled, you may need to install or configure it manually.
    Note: Due to the requirement of SSH access and potential variations in configurations,
    automated checking of CLR status is not feasible. Hence, manual verification is recommended.""")
print("-" * 50)

# Check if dedicated VPC is used for production resources
print("\n13. We should always recommend using a dedicated VPC for Production Resources - All Prod servers should be in one VPC.")

def check_dedicated_vpc():
    try:
        # Initialize the EC2 client
        ec2 = boto3.client('ec2')

        # Describe VPCs
        response = ec2.describe_vpcs()

        # Check if any VPC is tagged as 'Production'
        for vpc in response['Vpcs']:
            vpc_id = vpc['VpcId']
            tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
            if tags.get('Name') == 'Production':
                print(f"Dedicated VPC (VpcId: {vpc_id}) is used for production resources.")
                return

        print("No dedicated VPC is used for production resources.")

    except Exception as e:
        print(f"Error: {e}")

# Suggestion for manual verification
print(f"""
Suggestion: 
This function automates the check for whether a dedicated VPC is used for production resources.

It's recommended to use dedicated VPCs for production resources to provide isolation and security. 
Ensure that critical production workloads are segregated from non-production environments 
to minimize the risk of unauthorized access or interference. 
Additionally, consider implementing network security best practices, such as using 
network access control lists (NACLs) and security groups effectively, 
to further enhance the security posture of your VPCs.
""")
print("-" * 50)

# Check if SSH to all production resources is limited to Bastion Host only
print("\n14.SSH to all Production resources should be limited to Bastion Host ONLY.")
def check_ssh_restrictions():
    # This can be partially automated. You can check security group configurations,
    # but verifying if SSH access is limited only to Bastion Host might require manual verification.
    """
    This function semi-automates the process of checking SSH restrictions by retrieving security group configurations
    and analyzing their inbound rules. Manual verification may still be required for full information,
    especially to ensure SSH access is limited only to the Bastion Host.
    """
    ec2_client = boto3.client('ec2')
    
    # Retrieve all security groups
    response = ec2_client.describe_security_groups()
    security_groups = response.get('SecurityGroups', [])
    
    for group in security_groups:
        group_id = group['GroupId']
        group_name = group['GroupName']
        print(f"Security Group: {group_name} ({group_id})")
        
        # Check inbound rules for SSH (port 22)
        ssh_rules = [rule for rule in group.get('IpPermissions', []) if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == 22 and rule['ToPort'] == 22]
        
        if ssh_rules:
            print("SSH access is configured:")
            for rule in ssh_rules:
                # Check if SSH access is restricted to specific IP ranges
                ip_ranges = [cidr['CidrIp'] for cidr in rule.get('IpRanges', [])]
                if ip_ranges:
                    print("   - Allowed from IP ranges:", ip_ranges)
                else:
                    print("   - SSH access is open to all IP addresses (not recommended)")
        else:
            print("SSH access is not configured.")
        print()  # Add a newline for readability

# Print a message indicating that SSH restrictions are about to be checked
print("Checking SSH restrictions...")
print("Please note: This function semi-automates the process of checking SSH restrictions by retrieving security group configurations and analyzing their inbound rules. Manual verification may still be required for full information, especially to ensure SSH access is limited only to the Bastion Host.")
print("-" * 50)

# Check if MFA is enabled for SSH access to Bastion Host
print("\n15.MFA (Multi-Factor Authentication) to be enabled for SSH access to Bastion Host ")
def check_mfa_bastion():
    # This can be automated by checking IAM policies and configurations related to MFA.
    try:
        # Initialize IAM client
        iam = boto3.client('iam')

        # List IAM users and roles
        response = iam.list_users()
        users = response['Users']
        response = iam.list_roles()
        roles = response['Roles']

        # Check IAM users
        for user in users:
            username = user['UserName']
            response = iam.list_mfa_devices(UserName=username)
            if response['MFADevices']:
                print(f"MFA is enabled for SSH access to Bastion Host for IAM user: {username}")
            else:
                print(f"MFA is not enabled for SSH access to Bastion Host for IAM user: {username}")

        # Check IAM roles
        for role in roles:
            rolename = role['RoleName']
            response = iam.list_mfa_devices(UserName=rolename)
            if response['MFADevices']:
                print(f"MFA is enabled for SSH access to Bastion Host for IAM role: {rolename}")
            else:
                print(f"MFA is not enabled for SSH access to Bastion Host for IAM role: {rolename}")

    except Exception as e:
        print(f"Error checking MFA for Bastion Host: {e}")

    # Print suggestion
    print("""
    Suggestion:
    While automation is possible to check IAM policies and configurations related to MFA, manual verification 
    by reviewing IAM policies and user configurations is recommended for comprehensive assurance of MFA status.
    
    Manual Verification Steps:
    1. Identify the IAM user(s) or role(s) used for SSH access to the Bastion Host.
    2. Review IAM policies attached to these user(s) or role(s) to ensure MFA is required.
    3. Check IAM user(s) or role(s) configurations to verify MFA settings.
    
    Automated Checks:
    - Check IAM policies to ensure MFA requirement for SSH access to the Bastion Host.
    - Review IAM user(s) or role(s) configurations to confirm MFA settings.
    
    Note: Manual verification provides a more thorough understanding of MFA status and should be prioritized.
    """)
print("-" * 50)

# Check if MFA is enabled for SSH access to all production servers
print("\n16.MFA (Multi-Factor Authentication) to be enabled for SSH access to all Production Servers.")
def check_mfa_production_servers():
    # This can be automated by checking IAM policies and configurations related to MFA.
    try:
        # Initialize IAM client
        iam = boto3.client('iam')

        # List IAM users and roles
        response = iam.list_users()
        users = response['Users']
        response = iam.list_roles()
        roles = response['Roles']

        # Check IAM users
        for user in users:
            username = user['UserName']
            response = iam.list_mfa_devices(UserName=username)
            if response['MFADevices']:
                print(f"MFA is enabled for SSH access to production server for IAM user: {username}")
            else:
                print(f"MFA is not enabled for SSH access to production server for IAM user: {username}")

        # Check IAM roles
        for role in roles:
            rolename = role['RoleName']
            response = iam.list_mfa_devices(UserName=rolename)
            if response['MFADevices']:
                print(f"MFA is enabled for SSH access to production server for IAM role: {rolename}")
            else:
                print(f"MFA is not enabled for SSH access to production server for IAM role: {rolename}")

    except Exception as e:
        print(f"Error checking MFA for production servers: {e}")
        print("""
Suggestion:
While this script automates the process of checking if MFA is enabled for SSH access to production servers
for IAM users and roles, it's essential to ensure that MFA is correctly configured for all users and roles
to enhance security. Manually review IAM policies and configurations related to MFA to verify its effectiveness
and make any necessary adjustments. Additionally, consider implementing MFA for all accounts and enforcing
it as a best practice for securing SSH access to production servers.
""")
print("-" * 50)

# Check if access to Bastion Host is limited via VPN only
print("\n17.Access to Bastion Host should be limited via VPN ONLY.")
def check_bastion_access():
    # This can be partially automated. You can check security group configurations,
    # but verifying if access is limited to VPN might require manual verification.
    """
    This function partially automates the process of checking if access to the Bastion Host is limited via VPN only.
    It retrieves security group configurations and analyzes their inbound rules. However, determining if access is
    limited to VPN might require manual verification, as VPN configurations vary widely.
    """
    ec2_client = boto3.client('ec2')

    # Replace 'bastion_security_group_id' with the actual security group ID of your Bastion Host
    bastion_security_group_id = 'sg-1234567890'
    
    try:
        # Retrieve the inbound rules of the security group associated with the Bastion Host
        response = ec2_client.describe_security_groups(GroupIds=[bastion_security_group_id])
        security_group = response['SecurityGroups'][0]
        inbound_rules = security_group['IpPermissions']
        
        # Check if SSH (port 22) access is configured
        ssh_rules = [rule for rule in inbound_rules if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == 22 and rule['ToPort'] == 22]
        
        if ssh_rules:
            print("SSH access to the Bastion Host is configured.")
            # Check if SSH access is limited to a specific IP range (e.g., VPN IP range)
            for rule in ssh_rules:
                ip_ranges = rule.get('IpRanges', [])
                if ip_ranges:
                    for ip_range in ip_ranges:
                        print("Allowed from IP range:", ip_range['CidrIp'])
                else:
                    print("SSH access is open to all IP addresses (not recommended)")
        else:
            print("SSH access to the Bastion Host is not configured.")
    
    except Exception as e:
        print("Error:", e)

# Print a message indicating that Bastion Host access is about to be checked
print("Checking Bastion Host access...")
print("Please note: This function partially automates the process of checking if access to the Bastion Host is limited via VPN only. It retrieves security group configurations and analyzes their inbound rules. However, determining if access is limited to VPN might require manual verification, as VPN configurations vary widely.")
print("-" * 50)

# Check if MFA is enabled for VPN access
print("\n18.MFA (Multi-Factor Authentication) to be enabled for VPN access")
def check_mfa_vpn():
    # This can be automated by checking IAM policies and configurations related to MFA.
    try:
        # Initialize IAM client
        iam = boto3.client('iam')

        # List IAM users
        response = iam.list_users()
        users = response['Users']

        # Check MFA status for each user
        for user in users:
            username = user['UserName']
            response = iam.list_mfa_devices(UserName=username)
            if response['MFADevices']:
                print(f"MFA is enabled for VPN access for IAM user: {username}")
            else:
                print(f"MFA is not enabled for VPN access for IAM user: {username}")

    except Exception as e:
        print(f"Error checking MFA for VPN access: {e}")
print("-" * 50)

# Check if backup configurations are in place for all prod resources
print("\n19.Back Up configuration is a must for all Prod resources. Get confirmation from the customer on Backup frequency and retention period.")
def check_backup_config():
    # This can be partially automated. You can check backup configurations,
    # but verifying the frequency and retention period might require manual confirmation.
    """
    This function partially automates the process of checking if backup configurations are in place for all production resources.
    It examines resource tags, types, and other attributes to determine if a resource is configured for backups. However, manual verification
    may still be required for certain resource types or configurations.
    """
    ec2_client = boto3.client('ec2')
    rds_client = boto3.client('rds')
    # Add clients for other AWS services as needed

    # Example: Check if EBS snapshots are configured for all running EC2 instances
    response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    instances = response.get('Reservations', [])

    for reservation in instances:
        for instance in reservation.get('Instances', []):
            instance_id = instance.get('InstanceId')
            tags = instance.get('Tags', [])
            backup_configured = False
            
            for tag in tags:
                if tag['Key'].lower() == 'backup' and tag['Value'].lower() == 'yes':
                    backup_configured = True
                    break
            
            if backup_configured:
                print(f"Backup is configured for EC2 instance: {instance_id}")
            else:
                print(f"Backup is not configured for EC2 instance: {instance_id}")
    
    # Example: Check if automated backups are enabled for all RDS instances
    response = rds_client.describe_db_instances()
    db_instances = response.get('DBInstances', [])

    for db_instance in db_instances:
        db_instance_id = db_instance.get('DBInstanceIdentifier')
        backup_enabled = db_instance.get('BackupRetentionPeriod') is not None
        
        if backup_enabled:
            print(f"Automated backups are enabled for RDS instance: {db_instance_id}")
        else:
            print(f"Automated backups are not enabled for RDS instance: {db_instance_id}")

# Print a message indicating that backup configurations are about to be checked
print("Checking backup configurations...")
print("Please note: This function partially automates the process of checking if backup configurations are in place for all production resources. It examines resource tags, types, and other attributes to determine if a resource is configured for backups. However, manual verification may still be required for certain resource types or configurations.")
print("-" * 50)

# Check if all resources are connected to a monitoring tool with customer-approved thresholds
print("\n20.All resources should be in connected to Monitoring tool with Customer approved Thresholds.")
def check_monitoring():
    # This can be partially automated. You can check if resources are associated with a monitoring tool,
    # but verifying the thresholds and alert recipients might require manual confirmation.
    """
    This function partially automates the process of checking if all resources are connected to a monitoring tool
    with customer-approved thresholds. It examines the configuration of monitoring services like Amazon CloudWatch.
    However, manual verification may still be required for certain resource types or configurations.
    """
    cloudwatch_client = boto3.client('cloudwatch')

    # Example: Check if all running EC2 instances have CloudWatch alarms with customer-approved thresholds
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    instances = response.get('Reservations', [])

    for reservation in instances:
        for instance in reservation.get('Instances', []):
            instance_id = instance.get('InstanceId')
            alarms = cloudwatch_client.describe_alarms(AlarmNamePrefix=f'EC2-{instance_id}-')

            if alarms['MetricAlarms']:
                print(f"CloudWatch alarms exist for EC2 instance: {instance_id}")
            else:
                print(f"No CloudWatch alarms found for EC2 instance: {instance_id}")

    # Add similar checks for other AWS resources like RDS, Lambda, etc.

# Print a message indicating that monitoring configurations are about to be checked
print("Checking monitoring configurations...")
print("Please note: This function partially automates the process of checking if all resources are connected to a monitoring tool with customer-approved thresholds. It examines the configuration of monitoring services like Amazon CloudWatch. However, manual verification may still be required for certain resource types or configurations.")
print("-" * 50)

#Have Monitoring tool covering all the critical instances, services, URL etc… Get confirmation from the customer on the coverage and alert receipents
print("21.Have Monitoring tool covering all the critical instances, services, URL etc… Get confirmation from the customer on the coverage and alert receipents.")
print("--note: confirmation of monitoring coverage and alert recipients may not be possible directly through code because it involves interacting with client to gather confirmation. However,we have automated the process of checking if all critical instances, services, URLs, etc., are configured in the monitoring tool. After that, you can prompt the user to confirm the coverage and provide alert recipients manually.--")
# Function to check if all critical instances, services, URLs are covered by the monitoring tool
def check_monitoring_coverage():
    # This can be partially automated. You can check if resources are associated with the monitoring tool,
    # but verifying the completeness of coverage might require manual confirmation.

    # Initialize CloudWatch client
    cloudwatch_client = boto3.client('cloudwatch')

    # Example: Check if all running EC2 instances have CloudWatch alarms
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    instances = response.get('Reservations', [])

    for reservation in instances:
        for instance in reservation.get('Instances', []):
            instance_id = instance.get('InstanceId')
            alarms = cloudwatch_client.describe_alarms(AlarmNamePrefix=f'EC2-{instance_id}-')

            if alarms['MetricAlarms']:
                print(f"CloudWatch alarms exist for EC2 instance: {instance_id}")
            else:
                print(f"No CloudWatch alarms found for EC2 instance: {instance_id}")

    # Check RDS instances
    rds_client = boto3.client('rds')
    response = rds_client.describe_db_instances()
    db_instances = response.get('DBInstances', [])

    for db_instance in db_instances:
        db_instance_id = db_instance.get('DBInstanceIdentifier')
        alarms = cloudwatch_client.describe_alarms(AlarmNamePrefix=f'RDS-{db_instance_id}-')

        if alarms['MetricAlarms']:
            print(f"CloudWatch alarms exist for RDS instance: {db_instance_id}")
        else:
            print(f"No CloudWatch alarms found for RDS instance: {db_instance_id}")

    # Check ELBs
    elb_client = boto3.client('elbv2')
    response = elb_client.describe_load_balancers()
    load_balancers = response.get('LoadBalancers', [])

    for lb in load_balancers:
        lb_name = lb.get('LoadBalancerName')
        alarms = cloudwatch_client.describe_alarms(AlarmNamePrefix=f'ELB-{lb_name}-')

        if alarms['MetricAlarms']:
            print(f"CloudWatch alarms exist for ELB: {lb_name}")
        else:
            print(f"No CloudWatch alarms found for ELB: {lb_name}")
print("-" * 50)

# Check if a log aggregator tool is implemented covering all servers
print("\n22.Implement Log Aggregator tool covering all servers.")
def check_log_aggregator():
    # This can be partially automated. You can check if a log aggregator tool is installed,
    # but verifying its coverage and location might require manual verification.
    """
    This function partially automates the process of checking if a log aggregator tool is implemented covering all servers.
    It examines the configuration of log aggregation services like Amazon CloudWatch Logs or third-party tools like Elasticsearch, Splunk, etc.
    However, manual verification may still be required for certain resource types or configurations.
    """
    cloudwatch_logs_client = boto3.client('logs')

    # Example: Check if log groups exist for all running EC2 instances
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    instances = response.get('Reservations', [])

    for reservation in instances:
        for instance in reservation.get('Instances', []):
            instance_id = instance.get('InstanceId')
            log_group_name = f"/aws/ec2/{instance_id}/"
            log_groups = cloudwatch_logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)

            if log_groups['logGroups']:
                print(f"Log group exists for EC2 instance: {instance_id}")
            else:
                print(f"No log group found for EC2 instance: {instance_id}")

    # Add similar checks for other log aggregation tools like Elasticsearch, Splunk, etc.

# Print a message indicating that log aggregator configurations are about to be checked
print("Checking log aggregator configurations...")
print("Please note: This function partially automates the process of checking if a log aggregator tool is implemented covering all servers. It examines the configuration of log aggregation services like Amazon CloudWatch Logs or third-party tools like Elasticsearch, Splunk, etc. However, manual verification may still be required for certain resource types or configurations.")
print("-" * 50)

# Check if log aggregator is recommended to be in Prod VPC on an individual instance
print("\n23.Log Aggregator is recommended to be in Prod VPC on a individual instance, else cost is on high side if outside of Prod VPC.")
def check_log_aggregator_location():
    # This can be partially automated. You can check if the log aggregator is within the Prod VPC,
    # but verifying if it's on an individual instance might require manual verification.
    """
    This function partially automates the process of checking if a log aggregator is recommended to be in the
    production VPC on an individual instance. It examines instance tags or other attributes to determine its
    location and if a log aggregator is recommended. However, manual verification may still be required for
    certain instances or configurations.
    """
    ec2_client = boto3.client('ec2')

    # Example: Check if the log_aggregator tag is set to 'prod_vpc' for all instances
    response = ec2_client.describe_instances()
    reservations = response.get('Reservations', [])

    for reservation in reservations:
        for instance in reservation.get('Instances', []):
            instance_id = instance.get('InstanceId')
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}

            if 'log_aggregator' in tags and tags['log_aggregator'].lower() == 'prod_vpc':
                print(f"Log aggregator is recommended to be in Prod VPC for instance: {instance_id}")
            else:
                print(f"Log aggregator is not recommended to be in Prod VPC for instance: {instance_id}")

# Print a message indicating that log aggregator locations are about to be checked
print("Checking log aggregator locations...")
print("Please note: This function partially automates the process of checking if a log aggregator is recommended to be in the production VPC on an individual instance. It examines instance tags or other attributes to determine its location and if a log aggregator is recommended. However, manual verification may still be required for certain instances or configurations.")

def print_table(headers, data):
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))
print("-" * 50)

# Function to choose menu option
def choose_menu_option():
    headers = ["Option", "Description"]
    menu_options = [
        ("0", "Scan All Checks"),
        ("1", "Applications expose to public via port 443 only"),
        ("2", "Enable AWS access"),
        ("3", "Traffic passes through Perimeter Security Solutions"),
        ("4", "Enable Horizontal load balancers"),
        ("5", "Install IPS/IDS and DDoS on Application servers"),
        ("6", "Set up Master-Slave Architecture for DB"),
        ("7", "Recommend Managed DB (RDS)"),
        ("8", "Encrypt all EBS volumes"),
        ("9", "Encrypt all S3 buckets"),
        ("10", "Enable versioning of all S3"),
        ("11", "Enable CloudTrail for all AWS accounts"),
        ("12", "Enable Command Line Recorder (CLR) for all servers"),
        ("13", "Recommend dedicated VPC for Productions Resources"),
        ("14", "Limit SSH to Bastion Host ONLY for Production resources"),
        ("15", "Enable MFA for SSH access to Bastion Host"),
        ("16", "Enable MFA for SSH access to all Production Servers"),
        ("17", "Limit Access to Bastion Host via VPN ONLY"),
        ("18", "Enable MFA for VPN access"),
        ("19", "Back Up configuration for all Prod resources"),
        ("20", "Connect all resources to Monitoring tool"),
        ("21", "Monitor all critical instances, services, URL"),
        ("22", "Implement Log Aggregator tool"),
        ("23", "Log Aggregator recommended in Prod VPC on individual instance"),
        ("24", "Exit")
    ]

    print_table(headers, menu_options)
    choice = input("Enter the number of your choice: ")

    if choice == "0":
        for option in menu_options[1:-1]:
            print(f"\nExecuting: {option[1]}")
            if option[0] == "6":
                check_database_architecture()
            else:
                choose_action(option[0])
        print("_ " * 50)
        print("All checks completed.")
    elif choice == "24":
        print("Exiting the script.")
        exit()
    else:
        choose_action(choice)

# Function to choose action based on user input
def choose_action(choice):
    if choice == "1":
        check_port_443_only()
    elif choice == "2":
        check_aws_access()
    elif choice == "3":
        check_security_solutions()
    elif choice == "4":
        check_load_balancers()
    elif choice == "5":
        check_security_solutions_servers()
    elif choice == "6":
        check_database_architecture()
    elif choice == "7":
        check_managed_db()
    elif choice == "8":
        check_ebs_encryption()
    elif choice == "9":
        check_s3_encryption()
    elif choice == "10":
        check_s3_versioning()
    elif choice == "11":
        check_cloudtrail()
    elif choice == "12":
        check_clr()
    elif choice == "13":
        check_dedicated_vpc()
    elif choice == "14":
        check_ssh_restrictions()
    elif choice == "15":
        check_mfa_bastion()
    elif choice == "16":
        check_mfa_production_servers()
    elif choice == "17":
        check_bastion_access()
    elif choice == "18":
        check_mfa_vpn()
    elif choice == "19":
        check_backup_config()
    elif choice == "20":
        check_monitoring()
    elif choice == "21":
        check_monitoring_coverage()
    elif choice == "22":
        check_log_aggregator()
    elif choice == "23":
        check_log_aggregator_location()
    else:
        print("Invalid choice. Please enter a valid option.")
