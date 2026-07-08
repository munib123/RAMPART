# Vulnerability: Unrestricted Access to SQL on EC2
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-mssql.yaml`)

## Description
Identifies open inbound access to Microsoft SQL Server on Amazon EC2 instances. Checks for security groups allowing unrestricted access (0.0.0.0/0 or ::/0) on TCP port 1433, increasing risks to SQL databases.

## Secure Mitigation
Restrict inbound traffic on TCP port 1433 to known, secure IP addresses. Regularly review and update security group rules to maintain minimal access requirements.

