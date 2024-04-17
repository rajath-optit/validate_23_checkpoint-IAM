Check #	Checks
1	Applications should expose to public via port 443 only.

2	Enable the AWS access to the team as required . Developers should have least privileges access. (Read / Read/write / Root account). No need for Dev team to have access to AWS console.
3	All traffic from end user should pass the Perimeter Security Solutions such as WAF and AWS Shield.
4	Applications should be enabled with Horizontal load balancers (Auto scaling) to meet the surge in traffic.
5	Application servers to be installed with IPS/IDS and DDoS (Examples for solution are - TrendMicro Deep Security).
6	We should always have Master - Slave Architecture set up for DB.
7	We should always recommend to have Managed DB (Example : RDS).
8	Encrypt all EBS volumes.
9	Encrypt all S3 buckets.
10	Enable versioning of all S3.
11	Enable Cloud Trail for all AWS accounts.
12	Enable Command Line Recorder (CLR) for all servers.
13	We should always recommend to use dedicated VPC for Productions Resources - All Prod servers should be in one VPC.
14	SSH to all Production resources should be limited to Bastion Host ONLY.
15	MFA (Multi-Factor Authentication) to be enabled for SSH access to Bastion Host 
16	MFA (Multi-Factor Authentication) to be enabled for SSH access to all Production Servers.
17	Access to Bastion Host should be limited via VPN ONLY.
18	MFA (Multi-Factor Authentication) to be enabled for VPN access
19	Back Up configuration is a must for all Prod resources. Get confirmation from the customer on Backup frequency and retention period.
20	All resources should be in connected to Monitoring tool with Customer approved Thresholds.
21	Have Monitoring tool covering all the critical instances, services, URL etc… Get confirmation from the customer on the coverage and alert receipents.
22	Implement Log Aggregator tool covering all servers.
23	Log Aggregator is recommended to be in Prod VPC on a individual instance, else cost is on high side if outside of Prod VPC.
