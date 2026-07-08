# Vulnerability: Check for Unrestricted SQL Server Access
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-unrestricted-sqlserver-access.yaml`)

## Description
Ensure that Google Cloud VPC network firewall rules do not allow unrestricted access (0.0.0.0/0 on TCP port 1433). Restrict access to trusted IP addresses or ranges to implement the Principle of Least Privilege (POLP) and reduce the attack surface.

## Secure Mitigation
Update your VPC firewall rules to allow SQL Server traffic only from trusted IP addresses or ranges.

