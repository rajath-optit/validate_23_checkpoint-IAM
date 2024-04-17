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


ON CHOOSING 

```
###1.Check if applications expose to the public only via port 443
Security groups violating port 443 exposure:
Security Group ID: sg-1234567890
Security Group ID: sg-0987654321
Do you want to configure these security groups? (yes/no): yes
Security group sg-1234567890 configured successfully.
Security group sg-0987654321 configured successfully.
```
### 2.Enable the AWS access to the team as required . Developers should have least privileges access. (Read / Read/write / Root account). No need for Dev team to have access to AWS console.
```
Verifying AWS access management for the team:
Developers should have least privilege access (Read / Read-write / Root account).
No need for Dev team to have access to AWS console.
```

### 3.All traffic from end user should pass the Perimeter Security Solutions such as WAF and AWS Shield.
```
Checking security solutions...
Partially automating the check for association with WAF and AWS Shield.
Please note: This function partially automates the process of checking if traffic from end users passes through Perimeter Security Solutions such as WAF and AWS Shield. It checks for associations with WAF and AWS Shield, but verifying if all traffic passes through them might require network configuration verification, which cannot be fully automated.
```

### 4.Applications should be enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.
```
All Auto Scaling Groups are associated with load balancers.
Recommendation: It ensure that all applications are configured to use horizontal load balancers (Auto scaling) to effectively handle surges in traffic and improve availability and scalability.
```

5. **Check if application servers are installed with IPS/IDS and DDoS protection:**
   ```
   5.Application servers to be installed with IPS/IDS and DDoS (Examples for solution are - TrendMicro Deep Security).

   Please note: This function partially automates the process of checking if application servers are installed with IPS/IDS and DDoS protection. It remotely executes a command to check for the presence of security solutions like Snort IDS. However, ensuring the proper configuration and effectiveness of these solutions may require manual verification.
   
   Servers missing security solutions:
   - i-0abcdef0123456789: Missing IPS/IDS or DDoS protection
   - i-1abcdef0123456789: Missing IPS/IDS or DDoS protection
   Suggestion: Consider installing and configuring IPS/IDS or DDoS protection solutions on the affected servers.
   ```

6. **Check if Master-Slave architecture is set up for the database:**
   ```
   6.We should always have Master - Slave Architecture set up for DB.

   Enter the database host: example.com
   Enter the database port: 5432
   Enter the database username: user
   Enter the database password: ********
   Enter the database name: dbname
   The database type is: PostgreSQL
   The database is configured as a Master in a Master-Slave setup.
   ```

7. **Check if managed DB (RDS) is used:**
   ```
   7.We should always recommend to have Managed DB (Example : RDS).

   Managed databases (RDS instances) are being used.
   ```
   
8. **Check if EBS volumes are encrypted:**
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

### Function: Check if S3 buckets are encrypted
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

### Function: Check if versioning is enabled for all S3 buckets
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

### Function: Check if CloudTrail is enabled for all AWS accounts
```
11.Enable Cloud Trail for all AWS accounts.
Checking CloudTrail status for AWS account 123456789012...
CloudTrail is enabled for this account.
Checking CloudTrail status for AWS account 234567890123...
CloudTrail is not enabled for this account.
```

### Function: Check if dedicated VPC is used for production resources
```
13. We should always recommend using a dedicated VPC for Production Resources - All Prod servers should be in one VPC.
Dedicated VPC (VpcId: vpc-1234567890) is used for production resources.
```

### Function: Check if SSH to all production resources is limited to Bastion Host only
```
14.SSH to all Production resources should be limited to Bastion Host ONLY.
Security Group: Bastion-SG (sg-1234567890)
SSH access is configured:
   - Allowed from IP range: 10.0.0.0/16
```

### Function: Check if MFA is enabled for SSH access to Bastion Host
```
15.MFA (Multi-Factor Authentication) to be enabled for SSH access to Bastion Host 
MFA is enabled for SSH access to Bastion Host for IAM user: example_user
MFA is not enabled for SSH access to Bastion Host for IAM role: example_role
```

### Function: Check if MFA is enabled for SSH access to all production servers
```
16.MFA (Multi-Factor Authentication) to be enabled for SSH access to all Production Servers.
MFA is enabled for SSH access to production server for IAM user: example_user
MFA is not enabled for SSH access to production server for IAM role: example_role
```

### Function: Check if access to Bastion Host is limited via VPN only
```
17.Access to Bastion Host should be limited via VPN ONLY.
Checking Bastion Host access...
Please note: This function partially automates the process of checking if access to the Bastion Host is limited via VPN only. It retrieves security group configurations and analyzes their inbound rules. However, determining if access is limited to VPN might require manual verification, as VPN configurations vary widely.
Security Group: Bastion-SG (sg-1234567890)
SSH access to the Bastion Host is configured:
Allowed from IP range: 10.0.0.0/16
```
The output for each section would be as follows:

### 18.MFA (Multi-Factor Authentication) to be enabled for VPN access
```
MFA is enabled for VPN access for IAM user: <username>
MFA is not enabled for VPN access for IAM user: <username>
```
*(This output indicates whether MFA is enabled for VPN access for each IAM user.)*

### 19.Back Up configuration is a must for all Prod resources. Get confirmation from the customer on Backup frequency and retention period.
```
Backup is configured for EC2 instance: <instance_id>
Backup is not configured for EC2 instance: <instance_id>
Automated backups are enabled for RDS instance: <db_instance_id>
Automated backups are not enabled for RDS instance: <db_instance_id>
```
*(This output indicates whether backup configurations are in place for EC2 instances and RDS instances.)*

### 20.All resources should be in connected to Monitoring tool with Customer approved Thresholds.
```
CloudWatch alarms exist for EC2 instance: <instance_id>
No CloudWatch alarms found for EC2 instance: <instance_id>
CloudWatch alarms exist for RDS instance: <db_instance_id>
No CloudWatch alarms found for RDS instance: <db_instance_id>
```
*(This output indicates whether all resources are connected to a monitoring tool with customer-approved thresholds.)*

### 21.Have Monitoring tool covering all the critical instances, services, URL etc… Get confirmation from the customer on the coverage and alert recipients.
```
CloudWatch alarms exist for EC2 instance: <instance_id>
No CloudWatch alarms found for EC2 instance: <instance_id>
CloudWatch alarms exist for RDS instance: <db_instance_id>
No CloudWatch alarms found for RDS instance: <db_instance_id>
```
*(This output indicates whether the monitoring tool covers all critical instances, services, URLs, etc.)*

### 22.Implement Log Aggregator tool covering all servers.
```
Log group exists for EC2 instance: <instance_id>
No log group found for EC2 instance: <instance_id>
```
*(This output indicates whether a log aggregator tool is implemented covering all servers.)*

### 23.Log Aggregator is recommended to be in Prod VPC on a individual instance, else cost is on high side if outside of Prod VPC.
```
Log aggregator is recommended to be in Prod VPC for instance: <instance_id>
Log aggregator is not recommended to be in Prod VPC for instance: <instance_id>
```
*(This output indicates whether a log aggregator is recommended to be in the production VPC on an individual instance.)*
   
   
