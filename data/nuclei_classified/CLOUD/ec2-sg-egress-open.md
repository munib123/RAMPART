# Vulnerability: Open Egress in EC2 Security Group
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-sg-egress-open.yaml`)

## Description
Checks for unrestricted outbound/egress rules in Amazon EC2 security groups, highlighting potential over-permissive configurations.

## Secure Mitigation
Restrict egress traffic in EC2 security groups to only necessary IP addresses and ranges, adhering to the Principle of Least Privilege.

