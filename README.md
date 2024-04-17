Checks

1.Applications should expose to public via port 443 only.

2.Enable the AWS access to the team as required . Developers should have least privileges access. (Read / Read/write / Root account). No need for Dev team to have access to AWS console.

3.All traffic from end user should pass the Perimeter Security Solutions such as WAF and AWS Shield.

4.Applications should be enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.

5.Application servers to be installed with IPS/IDS and DDoS (Examples for solution are - TrendMicro Deep Security).

6.We should always have Master - Slave Architecture set up for DB.

7.We should always recommend to have Managed DB (Example : RDS).

8.Encrypt all EBS volumes.

9.Encrypt all S3 buckets.

10.Enable versioning of all S3.

11.Enable Cloud Trail for all AWS accounts.

12.Enable Command Line Recorder (CLR) for all servers.

13.We should always recommend to use dedicated VPC for Productions Resources - All Prod servers should be in one VPC.

14.SSH to all Production resources should be limited to Bastion Host ONLY.

15.MFA (Multi-Factor Authentication) to be enabled for SSH access to Bastion Host 

16.MFA (Multi-Factor Authentication) to be enabled for SSH access to all Production Servers.

17.Access to Bastion Host should be limited via VPN ONLY.

18.MFA (Multi-Factor Authentication) to be enabled for VPN access

19.Back Up configuration is a must for all Prod resources. Get confirmation from the customer on Backup frequency and retention period.

20.All resources should be in connected to Monitoring tool with Customer approved Thresholds.

21.Have Monitoring tool covering all the critical instances, services, URL etc… Get confirmation from the customer on the coverage and alert receipents.

22.Implement Log Aggregator tool covering all servers.

23.Log Aggregator is recommended to be in Prod VPC on a individual instance, else cost is on high side if outside of Prod VPC.

OUTPUT
```
╒══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
│ Option   │ Description                                                                                                  │
╞══════════╪═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
│ 0        │ Scan All Checks                                                                                              │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1        │ Check Permissions                                                                                            │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 2        │ Configure Security Groups                                                                                    │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 3        │ List IAM Users                                                                                               │
──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 4        │ Check AWS Access                                                                                             │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 5        │ List IAM Policies for User                                                                                   │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 6        │ List IAM Groups for User                                                                                     │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 7        │ Check CloudTrail Status                                                                                      │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 8        │ Get Recent CloudTrail Events                                                                                 │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 9        │ Check Security Solutions                                                                                    │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 10       │ Check Load Balancers                                                                                        │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 11       │ Check Security Solutions for Servers                                                                        │
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 12       │ Check Database Architecture                                                                                 │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 13       │ Check Managed DB (RDS)                                                                                      │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 14       │ Check EBS Encryption                                                                                        │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 15       │ Check S3 Encryption                                                                                         │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 16       │ Check S3 Versioning                                                                                         │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 17       │ Check CloudTrail for AWS Accounts                                                                           │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 18       │ Check CLR for Servers                                                                                       │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 19       │ Check Dedicated VPC for Production Resources                                                               │
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 20       │ Check SSH Restrictions                                                                                      │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 21       │ Check MFA for Bastion Host SSH Access                                                                       │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 22       │ Check MFA for Production Servers SSH Access                                                                 │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 23       │ Check Bastion Host Access                                                                                   │
├──────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 24       │ Exit                                                                                                        │
╘══════════╧══════════════════════════════════════════════════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
│ Enter the number of your choice: 
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
```

ON CHOOSING 

### 1.Check if applications expose to the public only via port 443
Report: Security Groups Violating Port 443 Exposure
```
These security groups allow inbound traffic on port 443 from any IP address (0.0.0.0/0 or ::/0).
This can potentially expose applications to the public, which might pose security risks.
Recommendation: Restrict inbound traffic on port 443 to specific IP ranges as needed.

Security groups violating port 443 exposure:
- Security Group ID: sg-1234567890
- Security Group ID: sg-0987654321

Do you want to configure these security groups? (yes/no): yes

Security group sg-1234567890 configured successfully.
Security group sg-0987654321 configured successfully.

Checkpoint 1: Applications expose to the public only via port 443 - Complete
------------------------------------------------checkpoint 1---------------------------------------------
```

### 2.Enable the AWS access to the team as required . Developers should have least privileges access. (Read / Read/write / Root account). No need for Dev team to have access to AWS console.
```Checkpoint 2: Enable AWS Access and Ensure Least Privilege for Developers

Verifying AWS access management for the team:
Developers should have least privilege access (Read / Read-write / Root account).
No need for Dev team to have access to AWS console.

IAM Users:
- user1
  Permissions:
  - Policy1
  Belongs to Groups:
  - Group1
- user2
  Permissions:
  - Policy2
  Belongs to Groups:
  - Group2

CloudTrail Status:
CloudTrail is enabled.

Recent CloudTrail Events:
- event1: EventName1 (2024-04-17)
- event2: EventName2 (2024-04-16)
--------------------------------------------------
```

### 3.All traffic from end user should pass the Perimeter Security Solutions such as WAF and AWS Shield.
```Checkpoint 3: Ensure All Traffic Passes through Perimeter Security Solutions

Checking security solutions for all running instances...

Checking instance i-1234567890...
WAF is associated with instance i-1234567890.
AWS Shield is associated with instance i-1234567890.

Checking instance i-0987654321...
WAF is not associated with instance i-0987654321.
Do you want to configure WAF for this instance? (yes/no): yes
WAF configured successfully for instance i-0987654321.
AWS Shield is associated with instance i-0987654321.

Recommendation:
- Ensure all running instances have WAF and AWS Shield associated for perimeter security.

--------------------------------------------------
```

### 4.Applications should be enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.
Checkpoint 4: Applications should be enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic
```
Checking load balancer associations for Auto Scaling Groups...
Auto Scaling Groups not associated with load balancers:
- Group1
- Group2

Do you want to configure a load balancer for these Auto Scaling Groups? (yes/no): yes
Configuring load balancers...
Adding load balancers to these Auto Scaling Groups can help distribute incoming traffic evenly across instances, improving application availability and fault tolerance.
Steps to configure load balancers:
1. Choose a suitable load balancer type (e.g., Application Load Balancer, Network Load Balancer).
2. Create a new load balancer or select an existing one.
3. Associate the load balancer with the Auto Scaling Group(s) that need to scale horizontally.
4. Configure health checks to monitor the instances behind the load balancer.
5. Optionally, set up listeners and routing rules to route traffic to the instances.
6. Test the configuration to ensure that traffic is distributed properly.
7. Monitor the load balancer and Auto Scaling Group performance regularly.

Manual configuration is recommended for optimal customization and control.
--------------------------------------------------
```

### 5.Check if application servers are installed with IPS/IDS and DDoS protection:
   ```
   5.Application servers to be installed with IPS/IDS and DDoS (Examples for solution are - TrendMicro Deep Security).

   Please note: This function partially automates the process of checking if application servers are installed with IPS/IDS and DDoS protection. It remotely executes a command to check for the presence of security solutions like Snort IDS. However, ensuring the proper configuration and effectiveness of these solutions may require manual verification.
   
   Servers missing security solutions:
   - i-0abcdef0123456789: Missing IPS/IDS or DDoS protection
   - i-1abcdef0123456789: Missing IPS/IDS or DDoS protection
   Suggestion: Consider installing and configuring IPS/IDS or DDoS protection solutions on the affected servers.
   ```

### 6.Check if Master-Slave architecture is set up for the database:
   ```

 6. We should always have Master - Slave Architecture set up for DB.
Enter the database host: [user input]
Enter the database port: [user input]
Enter the database username: [user input]
Enter the database password: [user input]
Enter the database name: [user input]
The database type is: PostgreSQL
The database is configured as a Master in a Master-Slave setup.

Manual Verification:
While this script can check for Master-Slave configuration, it's important to note that some configurations
may not be accurately detected or may require additional context. For critical systems, it's recommended
to manually review the database configuration or consult with a database administrator to ensure
correctness and reliability.

   ```

### 7.Check if managed DB (RDS) is used:
   ```
   7.We should always recommend to have Managed DB (Example : RDS).

   Managed databases (RDS instances) are being used.
   ```
   
### 8.Check if EBS volumes are encrypted:
   ```
   8.Encrypt all EBS volumes.

   Encrypted EBS volumes found:
   - vol-0123456789abcdef0
   - vol-abcdef0123456789

   Unencrypted EBS volumes found:
   - vol-9876543210fedcba0
   Do you want to encrypt these volumes? (yes/no): yes
   Volume vol-9876543210fedcba0 encrypted successfully.

   Recommendation:
   Encrypting EBS volumes adds an additional layer of security to your data.
   Encrypted volumes help protect sensitive information and ensure compliance with
   data privacy regulations. It is essential for maintaining the confidentiality
   and integrity of your data.
   ```
The output for each function will depend on the specific conditions encountered in the AWS environment. Here's how the output might look like for each function:

### 9.Function: Check if S3 buckets are encrypted
```
9.Encrypt all S3 buckets.
Encrypted S3 buckets found:
- bucket1
- bucket2

Unencrypted S3 buckets found:
- bucket3

Do you want to encrypt these buckets? (yes/no): yes
Bucket bucket3 encrypted successfully.

Recommendation:
Enabling server-side encryption (SSE) for S3 buckets adds an additional layer of
security to your data, ensuring that objects stored in the bucket are encrypted
at rest. It is essential for maintaining the confidentiality and integrity of
your data.
```

### 10.Function: Check if versioning is enabled for all S3 buckets
```
10.Enable versioning of all S3.
S3 buckets with versioning enabled:
- bucket1
- bucket2

S3 buckets with versioning disabled:
- bucket3

Do you want to enable versioning for these buckets? (yes/no): yes
Versioning enabled for bucket3.

Recommendation:
Enabling versioning for S3 buckets allows you to retain multiple versions
of an object in the bucket. This helps protect against accidental deletion
or modification of objects, providing a backup mechanism for data recovery.
```

### 11.Function: Check if CloudTrail is enabled for all AWS accounts
```
11.Enable Cloud Trail for all AWS accounts.
Checking CloudTrail status for AWS account 123456789012...
CloudTrail is enabled for this account.
Checking CloudTrail status for AWS account 234567890123...
CloudTrail is not enabled for this account.
```

### 13.Function: Check if dedicated VPC is used for production resources
```
13. We should always recommend using a dedicated VPC for Production Resources - All Prod servers should be in one VPC.
Dedicated VPC (VpcId: vpc-1234567890) is used for production resources.
```

### 14.Function: Check if SSH to all production resources is limited to Bastion Host only
```
14.SSH to all Production resources should be limited to Bastion Host ONLY.
Security Group: Bastion-SG (sg-1234567890)
SSH access is configured:
   - Allowed from IP range: 10.0.0.0/16
```

### 15.Function: Check if MFA is enabled for SSH access to Bastion Host
```
15.MFA (Multi-Factor Authentication) to be enabled for SSH access to Bastion Host 
MFA is enabled for SSH access to Bastion Host for IAM user: example_user
MFA is not enabled for SSH access to Bastion Host for IAM role: example_role
```

### 16.Function: Check if MFA is enabled for SSH access to all production servers
```
16.MFA (Multi-Factor Authentication) to be enabled for SSH access to all Production Servers.
MFA is enabled for SSH access to production server for IAM user: example_user
MFA is not enabled for SSH access to production server for IAM role: example_role
```

### 17.Function: Check if access to Bastion Host is limited via VPN only
```
17.Access to Bastion Host should be limited via VPN ONLY.
Checking Bastion Host access...
Please note: This function partially automates the process of checking if access to the Bastion Host is limited via VPN only. It retrieves security group configurations and analyzes their inbound rules. However, determining if access is limited to VPN might require manual verification, as VPN configurations vary widely.
Security Group: Bastion-SG (sg-1234567890)
SSH access to the Bastion Host is configured:
Allowed from IP range: 10.0.0.0/16
```

### 18.MFA (Multi-Factor Authentication) to be enabled for VPN access
```
MFA is enabled for VPN access for IAM user: <username>
MFA is not enabled for VPN access for IAM user: <username>
```

### 19.Back Up configuration is a must for all Prod resources. Get confirmation from the customer on Backup frequency and retention period.
```
Backup is configured for EC2 instance: <instance_id>
Backup is not configured for EC2 instance: <instance_id>
Automated backups are enabled for RDS instance: <db_instance_id>
Automated backups are not enabled for RDS instance: <db_instance_id>
```

### 20.All resources should be in connected to Monitoring tool with Customer approved Thresholds.
```
CloudWatch alarms exist for EC2 instance: <instance_id>
No CloudWatch alarms found for EC2 instance: <instance_id>
CloudWatch alarms exist for RDS instance: <db_instance_id>
No CloudWatch alarms found for RDS instance: <db_instance_id>
```

### 21.Have Monitoring tool covering all the critical instances, services, URL etc… Get confirmation from the customer on the coverage and alert recipients.
```
CloudWatch alarms exist for EC2 instance: <instance_id>
No CloudWatch alarms found for EC2 instance: <instance_id>
CloudWatch alarms exist for RDS instance: <db_instance_id>
No CloudWatch alarms found for RDS instance: <db_instance_id>
```

### 22.Implement Log Aggregator tool covering all servers.
```
Log group exists for EC2 instance: <instance_id>
No log group found for EC2 instance: <instance_id>
```

### 23.Log Aggregator is recommended to be in Prod VPC on a individual instance, else cost is on high side if outside of Prod VPC.
```
Log aggregator is recommended to be in Prod VPC for instance: <instance_id>
Log aggregator is not recommended to be in Prod VPC for instance: <instance_id>
```
