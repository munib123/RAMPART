# Vulnerability: Restrict EC2 RDP Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-rdp.yaml`)

## Description
Check Amazon EC2 security groups for inbound rules that allow unrestricted RDP access and restrict access to trusted IPs.

## Secure Mitigation
Modify the EC2 security group rules to limit RDP access (TCP 3389) to known, trusted IP addresses or ranges.

