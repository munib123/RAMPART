# Vulnerability: Logs Router Encryption with Customer-Managed Keys Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-logs-router-cmek-not-enabled.yaml`)

## Description
Ensure that Google Cloud Logs Router data is encrypted with Customer-Managed Keys (CMKs) to provide full control over your data encryption and decryption process and to help meet compliance requirements. Using Cloud Key Management Service (Cloud KMS), you can create and manage your CMKs, ensuring secure and efficient encryption key management, controlled key rotation, and revocation mechanisms.

## Secure Mitigation
Enable Customer-Managed Keys (CMKs) for Logs Router encryption within your GCP organization by configuring Cloud KMS keys and associating them with the Logs Router service. Ensure the CMKs are properly managed and rotated per compliance requirements.

