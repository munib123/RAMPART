# Vulnerability: Azure SQL Server Auditing Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-sql-auditing-disabled.yaml`)

## Description
Ensure that the "Auditing" feature is enabled within your Microsoft Azure SQL server configuration settings in order to monitor your SQL databases for security, compliance, and troubleshooting purposes. Microsoft Azure allows an SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on that SQL server are audited.

## Secure Mitigation
Enable the "Auditing" feature in Azure SQL server settings to ensure comprehensive monitoring and compliance across all databases.

