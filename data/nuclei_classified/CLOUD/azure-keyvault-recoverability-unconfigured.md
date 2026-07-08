# Vulnerability: Key Vault Recoverability Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-keyvault-recoverability-unconfigured.yaml`)

## Description
Ensure that production Azure Key Vaults are recoverable to prevent permanent deletion/purging of encryption keys, secrets, and certificates stored within these vaults. To make your Azure Key Vault instances recoverable, you need to enable both "Soft Delete" and "Do Not Purge" features. "Soft Delete" ensures recoverability for 90 days post-deletion, whereas "Do Not Purge" prevents any purging of the vault and its contents.

## Secure Mitigation
Enable "Soft Delete" and "Do Not Purge" on all Azure Key Vaults to ensure they are recoverable and protected against permanent deletion.

