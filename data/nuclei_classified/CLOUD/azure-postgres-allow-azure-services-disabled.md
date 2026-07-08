# Vulnerability: Azure PostgreSQL Access From Azure Services Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-postgres-allow-azure-services-disabled.yaml`)

## Description
Ensure that the access from Microsoft Azure cloud services to Azure Database for PostgreSQL servers is disabled in order to secure access to PostgreSQL databases by allowing access from trusted Virtual Networks (Vnets) only.

## Secure Mitigation
Configure firewall rules to disable the "Allow access to Azure services" setting for Azure PostgreSQL Database servers to restrict access to trusted sources only.

