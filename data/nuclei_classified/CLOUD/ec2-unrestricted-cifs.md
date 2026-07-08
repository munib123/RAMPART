# Vulnerability: EC2 Unrestricted CIFS Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-cifs.yaml`)

## Description
Checks for inbound rules in Amazon EC2 security groups allowing unrestricted access (0.0.0.0/0 or ::/0) on TCP port 445, used for CIFS/SMB file sharing, posing a high security risk.

## Secure Mitigation
Restrict inbound access on TCP port 445 to known IPs or ranges. Regularly review security group configurations to ensure compliance with security policies.

