# Vulnerability: Unrestricted SSH Access in EC2
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-ssh.yaml`)

## Description
Checks for inbound rules in Amazon EC2 security groups that allow unrestricted SSH access (0.0.0.0/0 or ::/0) on TCP port 22, indicating a security risk by exposing the SSH server to the internet.

## Secure Mitigation
Restrict SSH access in EC2 security groups to trusted IP addresses or ranges, adhering to the Principle of Least Privilege (POLP) and mitigating the risk of unauthorized access.

