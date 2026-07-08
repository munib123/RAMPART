# Vulnerability: Unrestricted Oracle DB Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-oracle.yaml`)

## Description
Identifies unrestricted inbound access to Oracle databases in Amazon EC2 instances, which increases the risk of unauthorized access and attacks.

## Secure Mitigation
Restrict inbound traffic on TCP port 1521 to known IPs or ranges and employ strict access controls.

