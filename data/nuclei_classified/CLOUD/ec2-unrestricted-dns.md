# Vulnerability: Unrestricted DNS Access in EC2
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-dns.yaml`)

## Description
Checks for inbound rules in Amazon EC2 security groups that allow unrestricted access (0.0.0.0/0 or ::/0) on TCP/UDP port 53, which can expose DNS servers to potential attacks.

## Secure Mitigation
Restrict the inbound rules for TCP/UDP port 53 in EC2 security groups to known, trusted IPs only. Ensure security group rules are tightly controlled and monitored.

