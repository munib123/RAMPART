# Vulnerability: Missing SSL Certificate Auto-Renewal in Azure Key Vaults
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-ssl-autorenewal-missing.yaml`)

## Description
Microsoft Azure Key Vault service can renew your SSL certificates automatically to prevent application or service outages, credential leaks, or process violations that can disrupt your business. Ensure that your SSL certificates in Azure Key Vaults are set to auto-renew.

## Secure Mitigation
Configure SSL certificates in Azure Key Vaults to automatically renew by setting the correct policies in the Azure portal or through Azure CLI.

