# Vulnerability: Azure SQL MI TDE Not Using Customer-Managed Keys
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-sql-mi-tde-cmk-not-enabled.yaml`)

## Description
Ensure that Transparent Data Encryption (TDE) with Customer-Managed Keys (CMKs) is enabled for your Microsoft Azure SQL managed instances. The TDE protector configured for your Azure SQL managed instances must be encrypted with a Customer-Managed Key in order to protect your managed SQL databases with a key from your own Azure key vault. This enables you to have full control over the encryption and decryption process and meet strict compliance requirements.

## Secure Mitigation
Configure Transparent Data Encryption to use Customer-Managed Keys by setting the TDE protector to use a key from your Azure key vault for your SQL managed instances.

