# Vulnerability: Customer-Managed Key Not Configured for Azure Database Tier
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-database-tier-cmk-absent.yaml`)

## Description
Ensure that a Customer-Managed Key (CMK), also known as Bring Your Own Key (BYOK), is created and configured for your Microsoft Azure database tier to meet cloud security and compliance requirements within your organization. This check verifies if Azure database resources tagged with specific values use a CMK.

## Secure Mitigation
Configure a Customer-Managed Key for your Azure database tier by setting the appropriate policies through Azure portal or using Azure CLI.

