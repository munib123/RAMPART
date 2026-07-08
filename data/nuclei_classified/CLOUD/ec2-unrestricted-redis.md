# Vulnerability: Unrestricted Redis Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-redis.yaml`)

## Description
Checks for inbound rules in Amazon EC2 security groups that allow unrestricted access to Redis cache server instances on TCP port 6379.

## Secure Mitigation
Restrict inbound access to Redis instances by updating EC2 security group rules to allow only specific, trusted IP addresses.

