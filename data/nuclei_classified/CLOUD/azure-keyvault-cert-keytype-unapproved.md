# Vulnerability: Unapproved Certificate Key Type in Azure Key Vaults
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-cert-keytype-unapproved.yaml`)

## Description
Ensure that your Microsoft Azure Key Vault SSL certificates are using the allowed key type(s) for security and compliance purposes. Prior to running this rule by the Cloud Conformity engine, the allowed certificate key type(s) must be configured within the rule settings, on the Cloud Conformity account dashboard.

## Secure Mitigation
Review and update the certificate key types for your Azure Key Vault SSL/TLS certificates to align with approved key types through the Azure portal or Azure CLI.

