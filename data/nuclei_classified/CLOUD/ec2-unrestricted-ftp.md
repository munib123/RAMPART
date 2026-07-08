# Vulnerability: Restrict EC2 FTP Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-ftp.yaml`)

## Description
Ensure Amazon EC2 security groups disallow unrestricted inbound FTP access on TCP ports 20 and 21 to prevent brute force attacks.

## Secure Mitigation
Restrict inbound access on TCP ports 20 and 21 for EC2 security groups to known IPs or remove the rules if FTP is not required.

