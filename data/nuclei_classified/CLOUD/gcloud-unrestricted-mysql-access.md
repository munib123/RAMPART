# Vulnerability: Check for Unrestricted MySQL Database Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-mysql-access.yaml`)

## Description
Ensure that Google Cloud VPC network firewall rules do not allow unrestricted access (0.0.0.0/0 on TCP port 3306). Restrict MySQL traffic to trusted IP addresses or IP ranges to reduce the attack surface and enhance security.

## Secure Mitigation
Update your VPC firewall rules to allow MySQL traffic only from trusted IP addresses or ranges.

