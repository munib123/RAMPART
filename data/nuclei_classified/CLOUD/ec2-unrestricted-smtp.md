# Vulnerability: Unrestricted SMTP Access in EC2
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-smtp.yaml`)

## Description
Identifies unrestricted inbound access on TCP port 25 for EC2 security groups, which increases the risk of SMTP-related attacks.

## Secure Mitigation
Restrict TCP port 25 access to known, necessary IP addresses only. Avoid using 0.0.0.0/0 or ::/0 in security group rules.

