# Vulnerability: Cloud SQL Instance Encryption with Customer-Managed Keys Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-cmk-not-enabled.yaml`)

## Description
Ensure that your Google Cloud SQL database instances are encrypted with Customer-Managed Keys (CMKs) in order to have a fine control over your data encryption and decryption process. You can create and manage your own Customer-Managed Keys (CMKs) with Cloud Key Management Service (Cloud KMS). Cloud KMS provides secure and efficient encryption key management, controlled key rotation, and revocation mechanisms.

## Secure Mitigation
Configure Cloud SQL instances to use Customer-Managed Keys (CMKs) for encryption by enabling encryption with Cloud KMS and specifying a key for each database instance.

