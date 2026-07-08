# Vulnerability: Check for Unrestricted PostgreSQL Database Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-postgresql-access.yaml`)

## Description
Ensure that Google Cloud VPC network firewall rules do not allow unrestricted access (0.0.0.0/0 on TCP port 5432). Restrict PostgreSQL traffic to trusted IP addresses or IP ranges to implement the Principle of Least Privilege (POLP) and reduce the attack surface.

## Secure Mitigation
Update your VPC firewall rules to allow PostgreSQL traffic only from trusted IP addresses or ranges.

