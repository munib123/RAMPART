# Vulnerability: Unrestricted PostgreSQL Database Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-postgresql-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access on TCP port 5432, used by PostgreSQL Database Server, to prevent unauthorized database access.

## Secure Mitigation
Implement strict NSG rules to restrict access on TCP port 5432 to only trusted IPs. Consider using additional layers of security, such as VPNs or Azure Private Link, to enhance database security.

