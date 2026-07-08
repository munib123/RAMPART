# Vulnerability: Check for Unrestricted RDP Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-rdp-access.yaml`)

## Description
Ensure that Google Cloud VPC firewall rules do not allow unrestricted access (0.0.0.0/0 on TCP port 3389). Restrict RDP traffic to trusted IP addresses or IP ranges to reduce the attack surface and enhance security.

## Secure Mitigation
Update your VPC firewall rules to allow RDP traffic only from trusted IP addresses or ranges.

