# 23 Checks validate python
 
after pre-requisite installed, below documentation is how outputworks

### 1. Applications should expose to public via port 443 only.

#### Documentation:
This script will check all security groups in your AWS account and see if any of them allow inbound traffic on port 443 from any IP address. If it finds such a security group, it will return a message confirming that port 443 is allowed. Otherwise, it will return a message indicating that port 443 is not allowed.

#### Sample Outputs:
1. If port 443 is allowed:
```
Yes, Applications should expose to public via port 443 only in security group: <SecurityGroupName>.
```

2. If port 443 is not allowed:
```
No, no security group allows inbound traffic on port 443.
```

### 2. Enable the AWS access to the team as required. Developers should have least privileges access. (Read / Read/write / Root account). No need for Dev team to have access to AWS console.

#### Documentation:
This script will list all IAM users in the AWS account along with the policies attached to them (both attached and inline policies). However, determining the exact access level (e.g., 'Read' or 'Read/write') solely from the policy names would require additional analysis of the policy documents and possibly external context about the application and its requirements.

#### Sample Output:
```
Users with credentials:
- <UserName>:
  Attached Policies:
    - <PolicyName1>
    - <PolicyName2>
  Inline Policies:
    - <PolicyName3>
- <AnotherUserName>:
  Attached Policies:
    - <PolicyName4>
  Inline Policies:
    - <PolicyName5>
```

### 3. All traffic from end user should pass the Perimeter Security Solutions such as WAF and AWS Shield.

#### Documentation:
This script first checks if either CloudFront distributions or ALBs are associated with the application. If so, it then proceeds to check if AWS WAF and AWS Shield are enabled for the respective resource. If neither CloudFront nor ALB is associated, it prints a message indicating that this checkpoint cannot be scanned.

#### Sample Outputs:
1. If all traffic passes through AWS WAF and AWS Shield:
```
Yes, all traffic from end users passes through AWS WAF and AWS Shield.
```

2. If not all traffic passes through AWS WAF and AWS Shield:
```
No, not all traffic from end users passes through AWS WAF and AWS Shield.
```

### 4. Applications should be enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.

#### Documentation:
This script checks if there are any auto scaling groups associated with your application. If auto scaling groups are found, it indicates that your application is enabled with horizontal load balancers (auto scaling) to meet the surge in traffic. Otherwise, it indicates that this requirement is not met.

#### Sample Outputs:
1. If applications are enabled with Horizontal load balancers (Auto scaling):
```
Yes, applications are enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.
```

2. If applications are not enabled with Horizontal load balancers (Auto scaling):
```
No, applications are not enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.
```

### 5. Application servers to be installed with IPS/IDS and DDoS (Examples for solution are - TrendMicro Deep Security).

#### Documentation:
This script checks the security groups associated with the application servers. If the security groups have rules allowing HTTP (port 80) or HTTPS (port 443) traffic and rules allowing all traffic (which might indicate DDoS protection), it assumes that some level of security measures similar to IPS/IDS and DDoS protection is in place. However, this is a simplified approach and may not cover all scenarios or accurately determine the presence of specific security software like TrendMicro Deep Security.

#### Sample Outputs:
1. If application servers have some level of security measures such as IPS/IDS and DDoS protection:
```
Yes, application servers have some level of security measures such as IPS/IDS and DDoS protection.
```

2. If application servers do not have specific security measures such as IPS/IDS and DDoS protection:
```
No, application servers do not have specific security measures such as IPS/IDS and DDoS protection.
```

### 6. We should always have Master - Slave Architecture set up for DB.

#### Documentation:
This script checks all RDS DB instances in your AWS account and verifies if any of them have one or more read replicas. If read replicas are found, it indicates that a Master - Slave Architecture is set up for the database. Otherwise, it indicates that the requirement is not met.

#### Sample Outputs:
1. If Master - Slave Architecture is set up for the DB:
```
Yes, Master - Slave Architecture is set up for the DB.
```

2. If Master - Slave Architecture is not set up for the DB:
```
No, Master - Slave Architecture is not set up for the DB.
```

### 7. We should always recommend to have Managed DB (Example print(RDS).

#### Documentation:
This script iterates through the list of managed database options and checks for each one sequentially. If it finds any associated database, it returns True and prints the appropriate message. If none of the managed databases are found associated with the application, it prints a message indicating that no managed database is attached.

#### Sample Outputs:
1. If a managed

 database such as Amazon RDS, Amazon Aurora, or another option is associated with this application:
```
A managed database such as Amazon RDS, Amazon Aurora, or another option is associated with this application.
```

2. If no managed database such as Amazon RDS, Amazon Aurora, or any other option is associated with this application:
```
No managed database such as Amazon RDS, Amazon Aurora, or any other option is associated with this application.
```

### 8. Encrypt all EBS volumes.

#### Documentation:
This script checks if all EBS volumes in the AWS account are encrypted. If any volume is found to be unencrypted, it lists the volume IDs.

#### Sample Outputs:
1. If all EBS volumes are encrypted:
```
All EBS volumes are encrypted.
```

2. If not all EBS volumes are encrypted:
```
Not all EBS volumes are encrypted.
List of unencrypted EBS volumes:
- vol-12345678
- vol-87654321
```

### 9. Encrypt all S3 buckets.

#### Documentation:
This script checks if all S3 buckets in the AWS account are encrypted. If any bucket is found to be unencrypted, it lists the bucket names.

#### Sample Outputs:
1. If all S3 buckets are encrypted:
```
All S3 buckets are encrypted.
```

2. If not all S3 buckets are encrypted:
```
Not all S3 buckets are encrypted.
List of unencrypted S3 buckets:
- bucket1
- bucket2
```

These outputs should provide comprehensive information about the status of each check and any potential issues or compliance with the given requirements.

### 8. Encrypt all EBS volumes.

#### Documentation:
This script checks if all EBS volumes in the AWS account are encrypted. If any volume is found to be unencrypted, it lists the volume IDs.

#### Sample Output:
```
All EBS volumes are encrypted.
```
or
```
Not all EBS volumes are encrypted.
List of unencrypted EBS volumes:
- vol-12345678
- vol-87654321
```

### 9. Encrypt all S3 buckets.

#### Documentation:
This script checks if all S3 buckets in the AWS account are encrypted. If any bucket is found to be unencrypted, it lists the bucket names.

#### Sample Output:
```
All S3 buckets are encrypted.
```
or
```
Not all S3 buckets are encrypted.
List of unencrypted S3 buckets:
- bucket1
- bucket2
```

### 10. Enable versioning of all S3 buckets.

#### Documentation:
This script checks if versioning is enabled for all S3 buckets in the AWS account. If versioning is not enabled, it lists the bucket names.

#### Sample Output:
```
All S3 buckets have versioning enabled.
```
or
```
Not all S3 buckets have versioning enabled.
List of S3 buckets without versioning:
- bucket1
- bucket2
```

### 11. Enable CloudTrail for all AWS accounts.

#### Documentation:
This script checks if CloudTrail is enabled for all AWS accounts in the AWS organization. It lists the accounts without CloudTrail.

#### Sample Output:
```
CloudTrail is enabled for all AWS accounts.
```
or
```
CloudTrail is not enabled for all AWS accounts.
List of AWS accounts without CloudTrail:
- account1
- account2
```

### 12. Enable Command Line Recorder (CLR) for all servers.

#### Documentation:
This script checks if Command Line Recorder (CLR) is enabled for all managed instances in the AWS account. It lists the instances without CLR.

#### Sample Output:
```
Command Line Recorder (CLR) is enabled for all servers.
```
or
```
Command Line Recorder (CLR) is not enabled for all servers.
List of servers without CLR:
- instance1
- instance2
```

### 13. Recommend using a dedicated VPC for Production Resources.

#### Documentation:
This script checks if all instances tagged as 'production' are in the same VPC. It indicates whether all production servers are in one VPC.

#### Sample Output:
```
All production servers are in one VPC.
```
or
```
Not all production servers are in one VPC.
```

### 14. Limit SSH access to Production resources to Bastion Host ONLY.

#### Documentation:
This script checks if SSH inbound rules for production servers allow traffic only from a specified Bastion Host IP address.

#### Sample Output:
```
SSH access to all production resources is limited to the Bastion Host ONLY.
```
or
```
SSH access to production resources is NOT limited to the Bastion Host ONLY.
```

### 15. Enable MFA for SSH access to Bastion Host.

#### Documentation:
This script checks if Multi-Factor Authentication (MFA) is enabled for SSH access to the specified IAM user or role associated with the Bastion Host.

#### Sample Output:
```
Multi-Factor Authentication (MFA) is enabled for SSH access to the Bastion Host.
```
or
```
Multi-Factor Authentication (MFA) is NOT enabled for SSH access to the Bastion Host.
```

### 16. Enable MFA for SSH access to all Production Servers.

#### Documentation:
This script checks if Multi-Factor Authentication (MFA) is enabled for SSH access to all IAM users and groups within the AWS account.

#### Sample Output:
```
Multi-Factor Authentication (MFA) is enabled for SSH access to all production servers.
```
or
```
Multi-Factor Authentication (MFA) is NOT enabled for SSH access to all production servers.
List of IAM users and groups without MFA enabled:
- user1
- group1
```

### 17. Access to Bastion Host Limited to VPN Only

#### Documentation:
This script verifies if access to a Bastion Host is restricted to a VPN. It prompts for Bastion Host security group IDs and the VPN's IP range. Then, it checks if SSH access is restricted to the VPN's IP range.

#### Sample Output:
```
Do you want to manually input the security group IDs for the Bastion Host? (yes/no)
> yes
Please enter the security group IDs for the Bastion Host, separated by commas:
> sg-12345678,sg-87654321
Do you want to check if access to Bastion Host is limited via VPN ONLY? (yes/no):
> yes
Enter the IP range of your VPN in CIDR notation (e.g., 203.0.113.0/24):
> 203.0.113.0/24
Access to Bastion Host is limited via VPN ONLY.
```

### 18. MFA (Multi-Factor Authentication) for VPN Access

#### Documentation:
This script checks if Multi-Factor Authentication (MFA) is enabled for VPN access. It prompts for the IAM user or role associated with VPN access and examines attached IAM policies and groups to determine MFA status.

#### Sample Output:
```
Do you want to check if MFA is enabled for VPN access? (yes/no):
> yes
Enter the name of the IAM user or role associated with VPN access:
> vpn_user
Multi-Factor Authentication (MFA) is enabled for VPN access.
```

### 19. Back Up Configuration Confirmation

#### Documentation:
This check requires manual confirmation from the customer for backup frequency and retention period.

#### Sample Output:
```
'Back Up configuration' check, the script will indicate that it needs manual confirmation from the customer for backup frequency and retention period.
```

### 20. Monitoring Tool Connection

#### Documentation:
This check indicates that manual confirmation is required from the customer for backup frequency and retention period.

#### Sample Output:
```
check, the script will indicate that it needs manual confirmation from the customer for backup frequency and retention period.
```

### 21. Monitoring Tool Coverage

#### Documentation:
This check indicates that manual confirmation is required from the customer for backup frequency and retention period. Confirmation of monitoring coverage and alert recipients may not be possible directly through code because it involves interacting with the client to gather confirmation.

#### Sample Output:
```
check, the script will indicate that it needs manual confirmation from the customer for backup frequency and retention period.
--note: confirmation of monitoring coverage and alert recipients may not be possible directly through code because it involves interacting with the client to gather confirmation. However, we have automated the process of checking if all critical instances, services, URLs, etc., are configured in the monitoring tool. After that, you can prompt the user to confirm the coverage and provide alert recipients manually
```

### 22. Log Aggregator Tool Implementation

#### Documentation:
This function partially automates the process of checking if a log aggregator tool is implemented covering all servers. It examines the configuration of log aggregation services like Amazon CloudWatch Logs or third-party tools like Elasticsearch, Splunk, etc. However, manual verification may still be required for certain resource types or configurations.

#### Sample Output:
```
Do you want to check if the Log Aggregator tool is implemented? (yes/no):
> yes
Log group exists for EC2 instance: i-1234567890abcdef0
The Log Aggregator tool is implemented.
```

### 23. Log Aggregator Placement Recommendation

#### Documentation:
This function partially automates the process of checking if a log aggregator is recommended to be in the production VPC on an individual instance. It examines instance tags or other attributes to determine its location and if a log aggregator is recommended. However, manual verification may still be required for certain instances or configurations.

#### Sample Output:
```
Do you want to check if the Log Aggregator is placed correctly? (yes/no):
> yes
Log aggregator is recommended to be in Prod VPC for instance: i-1234567890abcdef0
```

These documentations provide an overview of each check along with sample outputs for reference.
