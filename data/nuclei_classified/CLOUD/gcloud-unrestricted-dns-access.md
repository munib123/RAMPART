# Vulnerability: Check for Unrestricted DNS Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-dns-access.yaml`)

## Description
Ensure that Google Cloud VPC network firewall rules do not allow unrestricted access (0.0.0.0/0) on TCP and UDP port 53. Restrict DNS traffic to trusted IP addresses or ranges to reduce the attack surface and enhance security.

## Secure Mitigation
Update your VPC firewall rules to allow DNS traffic only from trusted IP addresses or ranges.

