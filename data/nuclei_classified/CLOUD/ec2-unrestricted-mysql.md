# Vulnerability: Unrestricted MySQL Access on EC2
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-mysql.yaml`)

## Description
Identifies unrestricted inbound access to MySQL database servers on Amazon EC2 instances, specifically targeting TCP port 3306.

## Secure Mitigation
Restrict inbound access on TCP port 3306 to known, necessary IP addresses or ranges, and avoid using 0.0.0.0/0 or ::/0.

