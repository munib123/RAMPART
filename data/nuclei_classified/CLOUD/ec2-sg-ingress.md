# Vulnerability: Unrestricted Access on Uncommon EC2 Ports
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-sg-ingress.yaml`)

## Description
Ensure Amazon EC2 security groups do not allow unrestricted access (0.0.0.0/0, ::/0) on uncommon ports, protecting against brute force attacks on EC2 instances.

## Secure Mitigation
Restrict access to uncommon ports in EC2 security groups, permitting only necessary traffic and implementing stringent access controls.

