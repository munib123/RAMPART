# Vulnerability: Check for Unrestricted FTP Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-ftp-access.yaml`)

## Description
Ensure that Virtual Private Cloud (VPC) firewall rules do not allow unrestricted access (0.0.0.0/0) on TCP ports 20 and 21. Restrict FTP traffic to trusted IP addresses or IP ranges to reduce the attack surface and enhance security.

## Secure Mitigation
Update your VPC firewall rules to allow FTP traffic only from trusted IP addresses or ranges.

