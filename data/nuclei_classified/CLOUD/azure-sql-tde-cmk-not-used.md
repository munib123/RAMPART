# Vulnerability: Azure SQL TDE Protector Not Using BYOK
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-sql-tde-cmk-not-used.yaml`)

## Description
Ensure that your Microsoft Azure SQL server's Transparent Data Encryption protector (i.e. TDE master key) is encrypted with BYOK (Bring Your Own Key), also known as Customer-Managed Key (CMK), in order to protect your SQL databases with a key from your own Azure key vault. Using service-managed keys instead of BYOK can reduce control over encryption keys and security compliance.

## Secure Mitigation
Configure the Transparent Data Encryption (TDE) feature of your Azure SQL server to use a Customer-Managed Key (CMK) from your own Azure Key Vault.

