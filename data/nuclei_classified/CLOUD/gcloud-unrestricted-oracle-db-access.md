# Vulnerability: Check for Unrestricted Oracle Database Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-oracle-db-access.yaml`)

## Description
Ensure that Google Cloud VPC network firewall rules do not allow unrestricted access (0.0.0.0/0 on TCP port 1521). Restrict Oracle Database traffic to trusted IP addresses or IP ranges to reduce the attack surface and enhance security.

## Secure Mitigation
Update your VPC firewall rules to allow Oracle Database traffic only from trusted IP addresses or ranges.

