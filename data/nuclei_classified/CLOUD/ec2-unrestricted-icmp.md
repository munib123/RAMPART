# Vulnerability: Restrict EC2 ICMP Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-icmp.yaml`)

## Description
Checks for Amazon EC2 security groups with inbound rules allowing unrestricted ICMP access. Advises restricting ICMP to trusted IPs to uphold the Principle of Least Privilege and minimize the attack surface.

## Secure Mitigation
Modify EC2 security group rules to limit ICMP access to necessary, trusted IP addresses/ranges only.

