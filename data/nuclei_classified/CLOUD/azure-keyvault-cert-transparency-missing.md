# Vulnerability: Missing Certificate Transparency in Azure Key Vaults
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-cert-transparency-missing.yaml`)

## Description
Ensure that Certificate Transparency feature is enabled for all Azure Key Vault SSL/TLS certificates to adhere to web security best practices. Certificate Transparency (CT) is a new Internet standard that helps to make the Transport Layer Security (TLS) ecosystem publicly auditable.

## Secure Mitigation
Enable Certificate Transparency for all Azure Key Vault SSL/TLS certificates through the Azure portal or Azure CLI to meet the standards enforced by the Certification Authority Browser Forum (CA/Browser Forum).

