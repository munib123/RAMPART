# Vulnerability: Unrestricted NACL Outbound Traffic
**Classification:** CLOUD
**Source:** Nuclei Template (`nacl-outbound-restrict.yaml`)

## Description
Checks for Amazon VPC NACLs allowing outbound traffic to all ports, recommending restriction to necessary ports only.

## Secure Mitigation
Modify NACL outbound rules to limit traffic to only the ports required for legitimate business needs.

