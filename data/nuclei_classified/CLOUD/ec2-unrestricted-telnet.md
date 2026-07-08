# Vulnerability: Restrict EC2 Telnet Access
**Classification:** CLOUD
**Source:** Nuclei Template (`ec2-unrestricted-telnet.yaml`)

## Description
Checks for unrestricted inbound Telnet access (TCP port 23) in Amazon EC2 security groups, highlighting potential security risks.

## Secure Mitigation
Restrict inbound Telnet access by updating EC2 security group rules to allow only trusted IP ranges or disabling Telnet if not required.

