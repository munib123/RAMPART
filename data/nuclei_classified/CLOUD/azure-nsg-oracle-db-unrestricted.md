# Vulnerability: Unrestricted Oracle Database Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-oracle-db-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access on TCP port 1521, used for Oracle Database, to protect against unauthorized database access.

## Secure Mitigation
Modify NSG rules to restrict access on TCP port 1521. Implement strict access controls and monitor connections to ensure only authorized access.

