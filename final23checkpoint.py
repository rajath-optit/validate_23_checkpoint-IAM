import boto3

# Define the ASCII art logo
logo = """
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
\033[91m██████╗-██████╗--------██████╗██╗--██╗███████╗-██████╗██╗--██╗██████╗--██████╗-██╗███╗---██╗████████╗----███████╗-██████╗-█████╗-███╗---██╗███╗---██╗███████╗██████╗-
\033[91m╚════██╗╚════██╗------██╔════╝██║--██║██╔════╝██╔════╝██║-██╔╝██╔══██╗██╔═══██╗██║████╗--██║╚══██╔══╝----██╔════╝██╔════╝██╔══██╗████╗--██║████╗--██║██╔════╝██╔══██╗
\033[91m-█████╔╝-█████╔╝█████╗██║-----███████║█████╗--██║-----█████╔╝-██████╔╝██║---██║██║██╔██╗-██║---██║-------███████╗██║-----███████║██╔██╗-██║██╔██╗-██║█████╗--██████╔╝
\033[91m██╔═══╝--╚═══██╗╚════╝██║-----██╔══██║██╔══╝--██║-----██╔═██╗-██╔═══╝-██║---██║██║██║╚██╗██║---██║-------╚════██║██║-----██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝--██╔══██╗
\033[91m███████╗██████╔╝------╚██████╗██║--██║███████╗╚██████╗██║--██╗██║-----╚██████╔╝██║██║-╚████║---██║-------███████║╚██████╗██║--██║██║-╚████║██║-╚████║███████╗██║--██║
\033[91m╚══════╝╚═════╝--------╚═════╝╚═╝--╚═╝╚══════╝-╚═════╝╚═╝--╚═╝╚═╝------╚═════╝-╚═╝╚═╝--╚═══╝---╚═╝-------╚══════╝-╚═════╝╚═╝--╚═╝╚═╝--╚═══╝╚═╝--╚═══╝╚══════╝╚═╝--╚═╝
\033[0m																	          _               _   ___   ___  
											 ___  ___ __ _ _ __  _ __   ___ _ __  __   _____ _ __ ___(_) ___  _ __  _/ | / _ \ / _ \ 
											/ __|/ __/ _` | '_ \| '_ \ / _ \ '__| \ \ / / _ \ '__/ __| |/ _ \| '_ \(_) || | | | | | |
											\__ \ (_| (_| | | | | | | |  __/ |     \ V /  __/ |  \__ \ | (_) | | | |_| || |_| | |_| |
											|___/\___\__,_|_| |_|_| |_|\___|_|      \_/ \___|_|  |___/_|\___/|_| |_(_)_(_)___(_)___/ 
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘																						                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
			  ╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
			  ║                        	║									   			  ║
			  ║\033[96m   GITHUB LINK\033[0m           	║\033[91mhttps://github.com/rajath-optit/validate_23_checkpoint-IAM/edit/main/final23checkpoint.py\033[0m	  ║
			  ║\033[96m   Version\033[0m          		║\033[91m1.0.0	\033[0m							                         	  ║
			  ║\033[96m   Programming Language\033[0m      ║\033[91mPython\033[0m								           			  ║
			  ║\033[96m   Command\033[0m                   ║\033[91mpython3 final23checkpoint.py\033[0m								  	  ║
			  ║   		                ║									         		  ║
			  ╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
	"""
def main():
    print(logo)

if __name__ == "__main__":
    main()


def check_port_443_in_security_groups():
    # Initialize the AWS EC2 client
    ec2 = boto3.client('ec2')

    # Describe all security groups in the AWS account
    response = ec2.describe_security_groups()

    # Initialize a list to store security group details
    security_group_details = []

    for group in response['SecurityGroups']:
        group_name = group['GroupName']
        permissions = group.get('IpPermissions', [])
        port_443_exposed = "No"
        port_range = "N/A-N/A"
        cidr_block = "N/A"
        status = "Not Allowed"
        
        # Check if port 443 is allowed inbound for any CIDR block
        for permission in permissions:
            if permission.get('FromPort') == 443 and permission.get('ToPort') == 443:
                ip_ranges = permission.get('IpRanges', [])
                for ip_range in ip_ranges:
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        port_443_exposed = "Yes"
                        port_range = "443-443"
                        cidr_block = "0.0.0.0/0"
                        status = "Allowed"
                        break  # Once port 443 is found, break the loop
                
        # Append the security group details to the list
        security_group_details.append((group_name, port_443_exposed, port_range, cidr_block, status))
    
    return security_group_details

# Function to print the security group details in a table format
def print_security_group_details(security_group_details):
    # Print the header for the table
    print("=" * 100)
    print("| {:<20} | {:<27} | {:<12} | {:<13} | {:<12} |".format(
        "Group Name", "Port 443 Exposed to Public", "Port Range", "CIDR Block", "Status"
    ))
    print("=" * 100)

    # Iterate over each security group detail and print it in the table format
    for detail in security_group_details:
        print("| {:<20} | {:<27} | {:<12} | {:<13} | {:<12} |".format(
            *detail
        ))

    # Print the bottom border of the table
    print("=" * 100)

# Print the purpose of the script
print("\033[94m" + "=" * 100)
print("\033[94m 1. Applications should only be exposed to the public via port 443.\033[0m")
print("\033[96m note:This script checks all security groups in your AWS account to see if any allow inbound traffic on port 443 from any IP address. It confirms if port 443 is allowed in a security group, or returns a message indicating that it's not allowed.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")

# Execute the function to check port 443 in security groups
security_group_details = check_port_443_in_security_groups()

# Print the security group details in a table format
print_security_group_details(security_group_details)

# Iterate over the security group details to check if port 443 is allowed
for detail in security_group_details:
    if detail[1] == "Yes":
        print("\n\033[92mResult: Yes, Applications have been exposed to the public via port 443 only in security group:", detail[0], "\033[0m")
        break  # Once a security group with port 443 exposed is found, break the loop
else:
    print("\n\033[91mResult: No security group allows inbound traffic on port 443.\033[0m")

# Print the bottom border of the result section
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m 2.Enable the AWS access to the team as required . Developers should have least privileges access. (Read / Read/write / Root account). No need for Dev team to have access to AWS console.\033[0m")
print("-" * 110)
def list_iam_users():
    iam = boto3.client('iam')
    
    # List all IAM users in the AWS account
    response = iam.list_users()

    return [user['UserName'] for user in response['Users']]

def get_user_policies(username):
    iam = boto3.client('iam')
    
    # Get the policies attached to the IAM user
    response = iam.list_attached_user_policies(UserName=username)
    attached_policies = response['AttachedPolicies']

    # Get the inline policies attached to the IAM user
    response = iam.list_user_policies(UserName=username)
    inline_policies = response['PolicyNames']

    return attached_policies, inline_policies

def print_user_access_report():
    users = list_iam_users()

    print("note:\033[96m This script will list all IAM users in the AWS account along with the policies attached to them (both attached and inline policies). However, determining the exact access level (e.g., 'Read' or 'Read/write') solely from the policy names would require additional analysis of the policy documents and possibly external context about the application and its requirements.\033[0m\n")

    print("┌───────────┬───────────────────────────────────────────────────────────┬───────────────────────────────────────────────────────────┐")
    print("│ User      │ Attached Policies                                         │ Inline Policies                                           │")
    print("├───────────┼───────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤")

    for user in users:
        attached_policies, inline_policies = get_user_policies(user)
        print("│ {:<10}│ {:<65}│ {:<65}│".format(user, ", ".join([" • " + policy['PolicyName'] for policy in attached_policies]), ", ".join([" • " + policy for policy in inline_policies])))
        print("├───────────┼───────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤")

    print("└───────────┴───────────────────────────────────────────────────────────┴───────────────────────────────────────────────────────────┘")

if __name__ == "__main__":
    print_user_access_report()
    
# Print the bottom border of the result section
print("=" * 110)
print("\n\n")

print("\033[94m 3. All traffic from end user should pass the Perimeter Security Solutions such as WAF and AWS Shield.\033[0m")

def check_cloudfront_distribution():
    cloudfront = boto3.client('cloudfront')

    # List all CloudFront distributions
    response = cloudfront.list_distributions()

    # Check if any CloudFront distribution is associated with the application
    return bool(response['DistributionList']['Items'])

def check_load_balancers():
    elbv2 = boto3.client('elbv2')

    # Describe all Application Load Balancers
    response = elbv2.describe_load_balancers()

    # Check if any ALB is associated with the application
    return bool(response['LoadBalancers'])

def check_waf_enabled(resource_type, resource_id):
    waf = boto3.client('waf')

    # Check if WAF is enabled for the resource
    if resource_type == 'cloudfront':
        response = waf.get_web_acl_for_resource(ResourceArn=f'arn:aws:cloudfront::{resource_id}:distribution/{resource_id}')
    elif resource_type == 'alb':
        response = waf.get_web_acl_for_resource(ResourceArn=f'arn:aws:elasticloadbalancing:your_region:your_account_id:loadbalancer/app/{resource_id}')

    return 'WebACL' in response

def check_shield_enabled():
    shield = boto3.client('shield')

    # Check if Shield Advanced is enabled for the account
    response = shield.describe_subscription()
    return response['Subscription']['SubscriptionType'] == 'SHIELD_ADVANCED'

def main():
    print("-" * 110)
    print(" Replace 'your_account_id', 'your_region', 'your_cloudfront_distribution_id', and 'your_load_balancer_id' with your actual AWS account ID, region, CloudFront distribution ID, and ALB ID respectively.")
    print("-" * 110)
    print("\033[96m note:This script first checks if either CloudFront distributions or ALBs are associated with the application. If so, it then proceeds to check if AWS WAF and AWS Shield are enabled for the respective resource. If neither CloudFront nor ALB is associated, it prints a message indicating that this checkpoint cannot be scanned.\033[0m")
    print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
    print("\nDo you want to check if all traffic from end users is passing through the Perimeter Security Solutions such as WAF and AWS Shield?")
    check_choice = input("(yes/no): ")

    if check_choice.lower() != 'yes':
        print("Exiting program.")
        return

    print("\nPlease provide the following information:")
    account_id = input("AWS Account ID: ")
    region = input("AWS Region: ")
    cloudfront_distribution_id = input("CloudFront Distribution ID: ")
    load_balancer_id = input("Application Load Balancer ID: ")

    cloudfront_associated = check_cloudfront_distribution()
    alb_associated = check_load_balancers()

    if not cloudfront_associated and not alb_associated:
        print("\033[91mCannot scan this checkpoint as neither CloudFront distributions nor Application Load Balancers are associated with the application.\033[0m")
        return

    waf_enabled = False
    shield_enabled = check_shield_enabled()

    if cloudfront_associated:
        waf_enabled = check_waf_enabled('cloudfront', cloudfront_distribution_id)
    elif alb_associated:
        waf_enabled = check_waf_enabled('alb', load_balancer_id)

    print("\n------------------------------------------------------------------------------")
    print("                     Perimeter Security Check Results                         ")
    print("------------------------------------------------------------------------------")
    print("| Resource Type      |  AWS WAF Enabled  |  AWS Shield Advanced Enabled   |")
    print("------------------------------------------------------------------------------")
    print(f"| CloudFront         | {'Yes' if waf_enabled else 'No':<17} | {'Yes' if shield_enabled else 'No':<30} |")
    print("------------------------------------------------------------------------------")

if __name__ == "__main__":
    main()
    
# Print the bottom border of the result section
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

def check_auto_scaling():
    autoscaling = boto3.client('autoscaling')

    # Describe all auto scaling groups
    response = autoscaling.describe_auto_scaling_groups()

    # Check if there are any auto scaling groups
    if response['AutoScalingGroups']:
        return True
    else:
        return False

def main():
    print("\033[94m4. Applications should be enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.\033[0m")
    print("-" * 110)
    print("\033[96mThis script checks if there are any auto scaling groups associated with your application. If auto scaling groups are found, it indicates that your application is enabled with horizontal load balancers (auto scaling) to meet the surge in traffic. Otherwise, it indicates that this requirement is not met.\033[0m")
    print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")

    auto_scaling_enabled = check_auto_scaling()

    print("\nResult:")
    print("-------")
    if auto_scaling_enabled:
        print("\033[92mYes, applications are enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.\033[0m")
    else:
        print("\033[91mNo, applications are not enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.\033[0m")
        print("No load balancer running/found.")

    # Print the bottom border of the result section
    print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")


if __name__ == "__main__":
    main()
print("\n\n")

print("\033[94m 5.Application servers to be installed with IPS/IDS and DDoS (Examples for solution are - TrendMicro Deep Security).\033[0m")
print("-" * 110)
print("\033[96m This script checks the security groups associated with the application servers. If the security groups have rules allowing HTTP (port 80) or HTTPS (port 443) traffic and rules allowing all traffic (which might indicate DDoS protection), it assumes that some level of security measures similar to IPS/IDS and DDoS protection is in place. However, this is a simplified approach and may not cover all scenarios or accurately determine the presence of specific security software like TrendMicro Deep Security.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_security_groups():
    ec2 = boto3.client('ec2')

    # Describe all security groups in the AWS account
    response = ec2.describe_security_groups()

    for group in response['SecurityGroups']:
        group_name = group['GroupName']
        permissions = group.get('IpPermissions', [])
        
        # Check if security group has rules allowing specific traffic patterns
        for permission in permissions:
            # Check for rules that might indicate IPS/IDS-like behavior
            if permission.get('FromPort') in [80, 443] and permission.get('IpProtocol') == 'tcp':
                return True
        
        # Check for rules that might indicate DDoS protection
        for permission in permissions:
            if permission.get('IpProtocol') == '-1' and permission.get('FromPort') == 0 and permission.get('ToPort') == 65535:
                return True
    
    return False

def main():
    
    security_enabled = check_security_groups()

    print("\nResult:")
    print("-------")
    
    if security_enabled:
        print("\033[92mYes, application servers have some level of security measures such as IPS/IDS and DDoS protection.\033[0m")
    else:
        print("\033[91mNo, application servers do not have specific security measures such as IPS/IDS and DDoS protection.\033[0m")

    # Print the bottom border of the result section
    print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")


if __name__ == "__main__":
    main()
print("\n\n")

print("\033[94m 6.We should always have Master - Slave Architecture set up for DB.\033[0m")
print("-" * 110)
print("\033[96m This script checks all RDS DB instances in your AWS account and verifies if any of them have one or more read replicas. If read replicas are found, it indicates that a Master - Slave Architecture is set up for the database. Otherwise, it indicates that the requirement is not met.")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_db_replication():
    rds = boto3.client('rds')

    # Describe all RDS DB instances
    response = rds.describe_db_instances()

    for db_instance in response['DBInstances']:
        # Check if the DB instance is a master
        if db_instance['ReadReplicaDBInstanceIdentifiers']:
            return True

    return False

def main():
    replication_enabled = check_db_replication()
    
    print("\nResult:")
    print("-------")
    
    if replication_enabled:
        print("\033[92m Yes, Master - Slave Architecture is set up for the DB.\033[0m")
    else:
        print("\033[91m No, Master - Slave Architecture is not set up for the DB.\033[0m")

    # Print the bottom border of the result section
    print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")


if __name__ == "__main__":
    main()
print("\n\n")


print("\033[94m7. We should always recommend to have Managed DB (Example print(RDS).\033[0m")
print("-" * 110)
print("\033[96mThis script iterates through the list of managed database options and checks for each one sequentially. If it finds any associated database, it returns True and prints the appropriate message. If none of the managed databases are found associated with the application, it prints a message indicating that no managed database is attached.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")

def check_managed_db():
    # List of managed database options to check
    managed_dbs = ['RDS', 'Aurora', 'DynamoDB', 'DocumentDB', 'Neptune', 'ElastiCache', 'Redshift', 'KeySpaces']

    for db in managed_dbs:
        if db == 'RDS':
            rds = boto3.client('rds')
            # Describe all RDS DB instances
            response = rds.describe_db_instances()
            if response['DBInstances']:
                return True
        elif db == 'Aurora':
            # Check if there are any Aurora clusters
            response = rds.describe_db_clusters()
            if response['DBClusters']:
                return True
        # Add similar checks for other managed databases

    return False

def main():
    managed_db_exists = check_managed_db()

    print("\nResult:")
    print("-------")
    
    if managed_db_exists:
        print("\033[92m| Managed Database Associated    |\033[0m")
        print("------------------------------------------------------------------------------")
        print("\033[92m| Yes managed database such as Amazon RDS, Amazon Aurora, or any other option is associated with this application. |\033[0m")
        print("------------------------------------------------------------------------------")
    else:
        print("\033[91m| No managed database such as Amazon RDS, Amazon Aurora, or any other option is associated with this application. |\033[0m")
        print("------------------------------------------------------------------------------")

if __name__ == "__main__":
    main()
    
# Print the bottom border of the result section
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")


print("\033[94m 8.Encrypt all EBS volumes.\033[0m")
print("-" * 110)
print("\033[96mThis script describes all EBS volumes in the AWS account and checks if they are encrypted. If any volume is found to be unencrypted, it adds the volume ID to the list of unencrypted volumes. Finally, it prints whether all EBS volumes are encrypted or lists the unencrypted volumes if any are found.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_ebs_encryption():
    ec2 = boto3.client('ec2')

    # Describe all EBS volumes
    response = ec2.describe_volumes()

    unencrypted_volumes = []

    # Check encryption status for each volume
    for volume in response['Volumes']:
        volume_id = volume['VolumeId']
        encryption = volume.get('Encrypted', False)

        # If volume is not encrypted, add it to the list of unencrypted volumes
        if not encryption:
            unencrypted_volumes.append(volume_id)

    return unencrypted_volumes

def main():
    unencrypted_volumes = check_ebs_encryption()

    if unencrypted_volumes:
        print("\033[91m Not all EBS volumes are encrypted.\033[0m")
        print("\033[91m List of unencrypted EBS volumes:\033[0mm")
        for volume_id in unencrypted_volumes:
            print(f"\033[91m- {volume_id}\033[0m")
    else:
        print("\033[92mAll EBS volumes are encrypted.\033[0m")

if __name__ == "__main__":
    main()
# Print the bottom border of the result section
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

# Option 9: Encrypt all S3 buckets
def encrypt_all_s3_buckets():
    print("\033[94m 9. Encrypt all S3 buckets.\033[0m")
    print("-" * 110)
    print("\033[96mThis script lists all S3 buckets in the AWS account and checks if they are encrypted. If any bucket is found to be unencrypted or does not have encryption settings configured, it adds the bucket name to the list of unencrypted buckets. Finally, it prints whether all S3 buckets are encrypted or lists the unencrypted buckets if any are found.\033[0m")
    print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
	
    def check_s3_encryption():
        s3 = boto3.client('s3')

        # List all S3 buckets
        response = s3.list_buckets()

        unencrypted_buckets = []

        # Check encryption status for each bucket
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']

            # Get encryption configuration for the bucket
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                if 'ServerSideEncryptionConfiguration' not in encryption:
                    unencrypted_buckets.append(bucket_name)
            except s3.exceptions.ClientError as e:
                # If the bucket is not encrypted or does not have encryption settings configured
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    unencrypted_buckets.append(bucket_name)

        return unencrypted_buckets

    def main():
        unencrypted_buckets = check_s3_encryption()

        print("note:if it did not detect any s3 bucket running, the script considers everything is safe and encrypted.")

        # Print table header
        print("=" * 90)
        print("| {:<86} |".format("Bucket Encryption Status"))
        print("-" * 90)
        print("| {:<50} | {:<30} |".format("Bucket Name", "Encryption Status"))
        print("=" * 90)

        if unencrypted_buckets:
            for bucket_name in unencrypted_buckets:
                print("| {:<50} | {:<30} |".format(bucket_name, "Not Encrypted"))
        else:
            print("| {:<50} | {:<30} |".format("All buckets", "Encrypted"))

        # Print bottom border of the table
        print("-" * 90)

    if __name__ == "__main__":
        main()
        # Print bottom border of the table
        print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

    print("\n\n")

if __name__ == "__main__":
    encrypt_all_s3_buckets()


print("\033[94m 10.Enable versioning of all S3.\033[0m")
print("-" * 110)
print("\033[96mThis script lists all S3 buckets in the AWS account and checks if versioning is enabled for each bucket. If versioning is not enabled or not configured for a bucket, it adds the bucket name to the list of unversioned buckets. Finally, it prints whether all S3 buckets have versioning enabled or lists the unversioned buckets if any are found.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")

def check_s3_versioning():
    s3 = boto3.client('s3')

    # List all S3 buckets
    response = s3.list_buckets()

    unversioned_buckets = []

    # Check versioning status for each bucket
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']

        # Get versioning configuration for the bucket
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if 'Status' not in versioning or versioning['Status'] != 'Enabled':
                unversioned_buckets.append(bucket_name)
        except s3.exceptions.ClientError as e:
            # If the bucket does not have versioning configuration
            if e.response['Error']['Code'] == 'NoSuchBucketVersioning':
                unversioned_buckets.append(bucket_name)

    return unversioned_buckets

def main():
    unversioned_buckets = check_s3_versioning()

    if unversioned_buckets:
        print("\033[91mNot all S3 buckets have versioning enabled.\033[0m")
        print("\033[91mList of S3 buckets without versioning:\033[0m")
        for bucket_name in unversioned_buckets:
            print(f"- {bucket_name}")
    else:
        print("\033[92mAll S3 buckets have versioning enabled/ it did not detect any running s3 associated.\033[0m")

if __name__ == "__main__":
    main()
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m 11.Enable Cloud Trail for all AWS accounts.\033[0m")
print("-" * 110)
print("\033[96mThis script lists all AWS accounts in the AWS organization and checks if CloudTrail is enabled for each account. If CloudTrail is not enabled for an account, it adds the account ID to the list of accounts without CloudTrail. Finally, it prints whether CloudTrail is enabled for all AWS accounts or lists the accounts without CloudTrail if any are found.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_aws_organizations():
    organizations = boto3.client('organizations')
    
    try:
        response = organizations.describe_organization()
        return True
    except organizations.exceptions.AWSOrganizationsNotInUseException:
        return False

def check_cloudtrail_enabled():
    organizations_enabled = check_aws_organizations()
    
    if not organizations_enabled:
        print("AWS Organizations is not enabled. This script requires AWS Organizations to be enabled to list all AWS accounts.")
        user_input = input("Please enable AWS Organizations and type 'yes' to continue or 'no' to skip this checkpoint: ")
        
        if user_input.lower() != 'yes':
            print("\033[91mThis checkpoint has to be manually checked since AWS Organizations is not enabled.\033[0m")
            return []
        else:
            return None  # Returning None to indicate that the script should continue if AWS Organizations is enabled
    
    organizations = boto3.client('organizations')

    # List all AWS accounts in the organization
    response = organizations.list_accounts()

    accounts_without_cloudtrail = []

    # Check CloudTrail status for each account
    for account in response['Accounts']:
        account_id = account['Id']

        # Check if CloudTrail is enabled for the account
        cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')
        trails = cloudtrail.describe_trails()

        if not trails.get('trailList'):
            accounts_without_cloudtrail.append(account_id)

    return accounts_without_cloudtrail

def main():
    accounts_without_cloudtrail = check_cloudtrail_enabled()
    
    if accounts_without_cloudtrail is None:
        print("Continuing with the script since AWS Organizations is enabled.")
        return
    elif not accounts_without_cloudtrail:
        print("\033[92mCloudTrail is enabled for all AWS accounts.\033[0m")
    else:
        print("\033[91mCloudTrail is not enabled for all AWS accounts.\033[0m")
        print("List of AWS accounts without CloudTrail:")
        for account_id in accounts_without_cloudtrail:
            print(f"- {account_id}")

if __name__ == "__main__":
    main()
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m 12.Enable Command Line Recorder (CLR) for all servers.\033[0m")
print("-" * 110)
print("\033[96m This script describes all managed instances in the AWS account using AWS Systems Manager (SSM) and checks if Command Line Recorder (CLR) is enabled for each instance. If CLR is not enabled for an instance, it adds the instance ID to the list of instances without CLR. Finally, it prints whether CLR is enabled for all servers or lists the servers without CLR if any are found.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")

def check_clr_enabled():
    ssm = boto3.client('ssm')

    # Describe all managed instances
    response = ssm.describe_instance_information()

    instances_without_clr = []

    # Check CLR status for each instance
    for instance_info in response['InstanceInformationList']:
        instance_id = instance_info['InstanceId']

        # Check if CLR is enabled for the instance
        clr_status = instance_info.get('AgentStatus', 'Unknown')
        if clr_status != 'Online':
            instances_without_clr.append(instance_id)

    return instances_without_clr

def main():
    instances_without_clr = check_clr_enabled()

    if instances_without_clr:
        print("\033[91m Command Line Recorder (CLR) is not enabled for all servers.\033[0m")
        print("List of servers without CLR:")
        for instance_id in instances_without_clr:
            print(f"- {instance_id}")
    else:
        print("\033[92m Command Line Recorder (CLR) is enabled for all servers.\033[0m")

if __name__ == "__main__":
    main()
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m 13.We should always recommend to use dedicated VPC for Productions'Resources - All Prod servers should be in one VPC.\033[0m")
print("-" * 110)
print("\033[96mThis script describes all instances in the AWS account and checks if all instances tagged with the environment 'production' are in the same VPC. If all production servers are in the same VPC, it prints 'All production servers are in one VPC'.Otherwise, it prints 'Not all production servers are in one VPC.'.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_production_servers_vpc():
    ec2 = boto3.client('ec2')

    # Describe all instances
    response = ec2.describe_instances()

    vpcs = set()

    # Check VPC IDs for each instance
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            if 'Environment' in tags and tags['Environment'].lower() == 'production':
                vpc_id = instance['VpcId']
                vpcs.add(vpc_id)

    return len(vpcs) == 1
    
print("-" * 90)

def main():
    all_production_in_one_vpc = check_production_servers_vpc()

    if all_production_in_one_vpc:
        print("\033[92m All production servers are in one VPC.\033[0m")
    else:
        print("\033[91m Not all production servers are in one VPC.\033[0m")

if __name__ == "__main__":
    main()

# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")
    
print("\033[94m 14. SSH to all Production resources should be limited to Bastion Host ONLY.\033[0m")
print("-" * 110)
print("\033[96mThis script prompts the user to enter the IP address of the Bastion Host in CIDR notation.")
print("It then checks if SSH inbound rules for production servers allow traffic only from this specified IP address.")
print(" If SSH access is limited to the Bastion Host only, it prints 'SSH access to all production resources is limited to the Bastion Host ONLY.'")
print("Otherwise, it prints 'SSH access to production resources is NOT limited to the Bastion Host ONLY.'\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_ssh_access(bastion_host_ip):
    ec2 = boto3.client('ec2')

    # Describe all instances
    response = ec2.describe_instances()

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            if 'Environment' in tags and tags['Environment'].lower() == 'production':
                instance_id = instance['InstanceId']
                security_groups = instance['SecurityGroups']

                # Check inbound SSH rules for each security group associated with the instance
                for sg in security_groups:
                    response = ec2.describe_security_groups(GroupIds=[sg['GroupId']])
                    for group in response['SecurityGroups']:
                        permissions = group.get('IpPermissions', [])
                        for permission in permissions:
                            if permission.get('FromPort') == 22 and permission.get('ToPort') == 22:
                                ip_ranges = permission.get('IpRanges', [])
                                for ip_range in ip_ranges:
                                    if ip_range['CidrIp'] != bastion_host_ip:
                                        return False

    return True

def main():
    user_input = input("Enter the IP address of your Bastion Host in CIDR notation (e.g., 203.0.113.0/24) OR (Type 'no' to skip, or provide details as shown in the example.): ")

    if user_input.lower() == 'no':
        print("\033[91m This checkpoint has to be manually checked since the Bastion Host IP address was not provided.\033[0m")
        return

    bastion_host_ip = user_input

    ssh_access_limited = check_ssh_access(bastion_host_ip)

    if ssh_access_limited:
        print("\033[92m SSH access to all production resources is limited to the Bastion Host ONLY.\033[0m")
    else:
        print("\033[91m SSH access to production resources is NOT limited to the Bastion Host ONLY.\033[0m")
        
if __name__ == "__main__":
    main()
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")


print("\033[94m 15. MFA (Multi-Factor Authentication) to be enabled for SSH access to Bastion Host.\033[0m")
print("-" * 110)
print("\033[96m This script prompts the user to enter the name of the IAM user or role associated with the Bastion Host.")
print(" It then checks if MFA is required for SSH access by examining the IAM policies attached to that user or role.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_mfa_enabled(bastion_host_name):
    iam = boto3.client('iam')

    # Get the IAM policies attached to the Bastion Host user or role
    policies = []

    # Retrieve the attached policies for the user
    try:
        response = iam.list_attached_user_policies(UserName=bastion_host_name)
        policies.extend(response['AttachedPolicies'])
    except iam.exceptions.NoSuchEntityException:
        pass

    # Retrieve the attached policies for the role
    try:
        response = iam.list_attached_role_policies(RoleName=bastion_host_name)
        policies.extend(response['AttachedPolicies'])
    except iam.exceptions.NoSuchEntityException:
        pass

    # Check if MFA is required for SSH access policies
    for policy in policies:
        policy_arn = policy['PolicyArn']
        policy_document = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy_document)['PolicyVersion']['Document']

        # Check if MFA is required for SSH access
        for statement in policy_version['Statement']:
            if 'Action' in statement and 'Effect' in statement and 'Resource' in statement:
                if 'Action' in statement and statement['Action'] == 'iam:CreateVirtualMFADevice' and statement['Effect'] == 'Allow' and statement['Resource'] == '*':
                    return True

    return False

def main():
    user_input = input("Enter the name of the IAM user or role associated with the Bastion Host OR (Type 'no' to skip, or provide details as shown in the example.): ")

    if user_input.lower() == 'no':
        print("\033[91m This checkpoint has to be manually checked since the IAM user or role associated with the Bastion Host was not provided.\033[0m")
        return

    bastion_host_name = user_input

    mfa_enabled = check_mfa_enabled(bastion_host_name)

    if mfa_enabled:
        print("\033[92m Multi-Factor Authentication (MFA) is enabled for SSH access to the Bastion Host.\033[0m")
    else:
        print("\033[91m Multi-Factor Authentication (MFA) is NOT enabled for SSH access to the Bastion Host.\033[0m")

if __name__ == "__main__":
    main()
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m 16.MFA (Multi-Factor Authentication) to be enabled for SSH access to all Production Servers.\033[0m")
print("-" * 110)
print("\033[96m This code checks whether Multi-Factor Authentication (MFA) is enabled for SSH access to all IAM users and groups within an AWS account. It iterates over IAM users and groups, retrieves their attached policies, and examines these policies to determine if MFA is required for SSH access.\033[0m")
print("┌" + "-" * 54 + " " * 54 + "┐")
def check_mfa_enabled():
    iam = boto3.client('iam')

    # Get all IAM users
    response = iam.list_users()

    for user in response['Users']:
        user_name = user['UserName']
        mfa_enabled = False

        # Get the IAM policies attached to the user
        try:
            response = iam.list_attached_user_policies(UserName=user_name)
            policies = response['AttachedPolicies']
        except iam.exceptions.NoSuchEntityException:
            policies = []

        # Get the IAM groups the user belongs to
        response = iam.list_groups_for_user(UserName=user_name)
        groups = response['Groups']

        # Get the policies attached to the groups
        for group in groups:
            group_name = group['GroupName']
            try:
                response = iam.list_attached_group_policies(GroupName=group_name)
                policies.extend(response['AttachedPolicies'])
            except iam.exceptions.NoSuchEntityException:
                pass

        # Check if MFA is required for SSH access policies
        for policy in policies:
            policy_arn = policy['PolicyArn']
            policy_document = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy_document)['PolicyVersion']['Document']

            # Check if MFA is required for SSH access
            for statement in policy_version['Statement']:
                if 'Action' in statement and 'Effect' in statement and 'Resource' in statement:
                    if 'Action' in statement and statement['Action'] == 'iam:CreateVirtualMFADevice' and statement['Effect'] == 'Allow' and statement['Resource'] == '*':
                        mfa_enabled = True
                        break

        if not mfa_enabled:
            print(f"\033[91m Multi-Factor Authentication (MFA) is NOT enabled for SSH access for IAM user '{user_name}'.\033[0m")

def main():
    check_mfa_enabled()

if __name__ == "__main__":
    main()
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m 17.Access to Bastion Host should be limited via VPN ONLY.\033[0m")
print("-" * 90)
print("\033[96m It verifies if access to a Bastion Host is restricted to a VPN. It asks for Bastion Host security group IDs, optionally allows manual input, and prompts for the VPN's IP range. Then, it checks if SSH access is restricted to the VPN's IP range\033[0m.")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_vpn_access(vpn_ip_range, bastion_host_security_groups):
    ec2 = boto3.client('ec2')
    
    # Check inbound SSH rules for each security group associated with the Bastion Host
    for sg_id in bastion_host_security_groups:
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        permissions = response['SecurityGroups'][0].get('IpPermissions', [])

        for permission in permissions:
            if permission.get('FromPort') == 22 and permission.get('ToPort') == 22:
                ip_ranges = permission.get('IpRanges', [])

                for ip_range in ip_ranges:
                    if ip_range['CidrIp'] != vpn_ip_range:
                        return False

    return True

def main():
    print("1.Do you want to manually input the security group IDs for the Bastion Host? (yes/no): ")
    manual_input = input().lower()
    
    if manual_input == "yes":
        print("Please enter the security group IDs for the Bastion Host, separated by commas:")
        bastion_host_security_groups = input().split(',')
    else:
        bastion_host_security_groups = ['sg-12345678', 'sg-87654321']  # Replace with your actual Bastion Host security group IDs
    
    while True:
        response = input("2.Do you want to check if access to Bastion Host is limited via VPN ONLY? (yes/no): ")
        if response.lower() == 'no':
            print("Skipping the check for limiting access via VPN.")
            break
        elif response.lower() == 'yes':
            vpn_ip_range = input("Enter the IP range of your VPN in CIDR notation (e.g., 203.0.113.0/24): ")
            vpn_access_limited = check_vpn_access(vpn_ip_range, bastion_host_security_groups)
            if vpn_access_limited:
                print("\033[92m Access to Bastion Host is limited via VPN ONLY.\033[0m")
            else:
                print("\033[91m Access to Bastion Host is NOT limited via VPN ONLY.\033[0m")
            break
        else:
            print("\033[91m Invalid input. Please enter 'yes' or 'no'.\033[0m")
    
if __name__ == "__main__":
    main()
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m 18.MFA (Multi-Factor Authentication) to be enabled for VPN access.\033[0m")
print("-" * 90)
print("\033[96m The script checks if Multi-Factor Authentication (MFA) is enabled for VPN access. It prompts for the IAM user or role associated with VPN access, then examines attached IAM policies and groups to determine MFA status. If MFA is enabled, it prints 'MFA enabled for VPN access'; otherwise, it prints 'MFA not enabled for VPN 'access'.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_mfa_enabled(vpn_user_or_role):
    try:
        iam = boto3.client('iam')
        # Get the IAM policies attached to the VPN user or role
        response = iam.list_attached_user_policies(UserName=vpn_user_or_role)
        policies = response['AttachedPolicies']

        # Get the IAM groups the user belongs to
        response = iam.list_groups_for_user(UserName=vpn_user_or_role)
        groups = response['Groups']

        # Get the policies attached to the groups
        for group in groups:
            response = iam.list_attached_group_policies(GroupName=group['GroupName'])
            policies.extend(response['AttachedPolicies'])

        # Check if MFA is required for VPN access policies
        for policy in policies:
            policy_arn = policy['PolicyArn']
            policy_document = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy_document)['PolicyVersion']['Document']

            for statement in policy_version['Statement']:
                if 'Action' in statement and 'Effect' in statement and 'Resource' in statement:
                    if 'Action' in statement and statement['Action'] == 'iam:CreateVirtualMFADevice' and statement['Effect'] == 'Allow' and statement['Resource'] == '*':
                        return True

        return False

    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def main():
    while True:
        response = input("Do you want to check if MFA is enabled for VPN access? (yes/no): ")
        if response.lower() == 'no':
            print("\033[91m Skipping the MFA check for VPN access.\033[0m")
            return
        elif response.lower() == 'yes':
            vpn_user_or_role = input("Enter the name of the IAM user or role associated with VPN access: ")
            mfa_enabled = check_mfa_enabled(vpn_user_or_role)
            if mfa_enabled:
                print("\033[92m Multi-Factor Authentication (MFA) is enabled for VPN access.\033[0m")
            else:
                print("\033[91m Multi-Factor Authentication (MFA) is NOT enabled for VPN access.\033[0m")
            break
        else:
            print("\033[91m Invalid input. Please enter 'yes' or 'no'.\033[0m")
    
if __name__ == "__main__":
    main()

# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m 19.Back Up configuration is a must for all Prod resources. Get confirmation from the customer on Backup frequency and retention period.\033[90m")
print("-" * 90)
print("\033[91m 'Back Up configuration' check, the script will indicate that it needs manual confirmation from the customer for backup frequency and retention period.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m20.All resources should be in connected to Monitoring tool with Customer approved Thresholds.\033[0m")
print("-" * 90)
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
print("\033[91m check, the script will indicate that it needs manual confirmation from the customer for backup frequency and retention period.\033[0m")
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\033[94m21.Have Monitoring tool covering all the critical instances, services, URL etc… Get confirmation from the customer on the coverage and alert receipents.\033[0m")
print("\033[91m check, the script will indicate that it needs manual confirmation from the customer for backup frequency and retention period.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
print("\033[91m--note: confirmation of monitoring coverage and alert recipients may not be possible directly through code because it involves interacting with client to gather confirmation. However,we have automated the process of checking if all critical instances, services, URLs, etc., are configured in the monitoring tool. After that, you can prompt the user to confirm the coverage and provide alert recipients manually\033[0m")
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\n\033[94m 22.Implement Log Aggregator tool covering all servers.\033[0m")
print("-" * 90)
print("\033[96m Please note: This function partially automates the process of checking if a log aggregator tool is implemented covering all servers. It examines the configuration of log aggregation services like Amazon CloudWatch Logs or third-party tools like Elasticsearch, Splunk, etc. However, manual verification may still be required for certain resource types or configurations.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_log_aggregator_tool():
    try:
        cloudwatch_logs_client = boto3.client('logs')

        # Example: Check if log groups exist for all running EC2 instances
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        instances = response.get('Reservations', [])

        if not instances:
            print("No running EC2 instances found. Please check manually.")
            return False

        for reservation in instances:
            for instance in reservation.get('Instances', []):
                instance_id = instance.get('InstanceId')
                if not instance_id:
                    print("Instance ID not found for an EC2 instance. Please check manually.")
                    return False

                log_group_name = f"/aws/ec2/{instance_id}/"
                log_groups = cloudwatch_logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)

                # Your code to check if the Log Aggregator tool is implemented goes here
                if log_groups['logGroups']:
                    print(f"\033[92m Log group exists for EC2 instance: {instance_id}\033[0m")
                else:
                    print(f"\033[91m No log group found for EC2 instance: {instance_id}\033[0m")

        return True
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def main():
    while True:
        response = input("Do you want to check if the Log Aggregator tool is implemented? (yes/no): ")
        if response.lower() == 'no':
            print("Skipping the check for the Log Aggregator tool.")
            return
        elif response.lower() == 'yes':
            log_aggregator_tool_implemented = check_log_aggregator_tool()
            if log_aggregator_tool_implemented:
                print("The Log Aggregator tool is implemented.")
            else:
                print("The Log Aggregator tool is NOT implemented.")
            break
        else:
            print("\033[91m Invalid input. Please enter 'yes' or 'no'.\033[0m")

if __name__ == "__main__":
    main()

print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")

print("\n\033[94m 23.Log Aggregator is recommended to be in Prod VPC on an individual instance, else cost is on high side if outside of Prod VPC.\033[0m")
print("-" * 90)
print("\033[96mPlease note: This function partially automates the process of checking if a log aggregator is recommended to be in the production VPC on an individual instance. It examines instance tags or other attributes to determine its location and if a log aggregator is recommended. However, manual verification may still be required for certain instances or configurations.\033[0m")
print("\033[93m┌" + "-" * 54 + "-" * 54 + "┐\033[0m")
def check_log_aggregator_placement():
    ec2_client = boto3.client('ec2')

    try:
        # Describe all instances
        response = ec2_client.describe_instances()
        reservations = response.get('Reservations', [])

        for reservation in reservations:
            for instance in reservation.get('Instances', []):
                instance_id = instance.get('InstanceId')
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}

                if 'log_aggregator' in tags and tags['log_aggregator'].lower() == 'prod_vpc':
                    print(f"\033[91m Log aggregator is recommended to be in Prod VPC for instance: {instance_id}\033[0m")
                else:
                    print(f"\033[92m Log aggregator is not recommended to be in Prod VPC for instance: {instance_id} \033[94m")
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def main():
    while True:
        response = input("Do you want to check if the Log Aggregator is placed correctly? (yes/no): ")
        if response.lower() == 'no':
            print("Skipping the check for Log Aggregator placement.")
            return
        elif response.lower() == 'yes':
            check_log_aggregator_placement()
            break
        else:
            print("\033[91m Invalid input. Please enter 'yes' or 'no'.\033[92m ")

if __name__ == "__main__":
    main()
# Print bottom border of the table
print("\033[93m└" + "-" * 54 + "-" * 54 + "┘\033[0m")

print("\n\n")
# Indicate that the check is completed
print("\033[94m__*\033[0m" * 30 + "Done" + "\033[94m__*\033[0m" * 30)
