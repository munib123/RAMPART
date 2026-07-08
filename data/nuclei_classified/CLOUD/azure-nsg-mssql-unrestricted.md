# Vulnerability: Unrestricted MS SQL Server Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-mssql-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access on TCP port 1433, used by Microsoft SQL Server, to protect against unauthorized database access and potential data breaches.

## Secure Mitigation
Restrict access to MS SQL Server by configuring NSG rules to only allow trusted sources to connect on TCP port 1433. Implement robust monitoring and alerting mechanisms to detect unauthorized access attempts.

