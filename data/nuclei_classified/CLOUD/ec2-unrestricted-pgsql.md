# Vulnerability: Unrestricted PostgreSQL Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-pgsql.yaml`)

## Description
Identifies unrestricted inbound access to PostgreSQL databases in Amazon EC2 security groups, which can expose databases to security risks.

## Secure Mitigation
Restrict inbound traffic to PostgreSQL servers by setting stringent rules in EC2 security groups, limiting access to specific IPs or ranges.

