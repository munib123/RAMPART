# Vulnerability: Filestore Instance Not Using Customer-Managed Encryption Keys
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-filestore-no-cmek.yaml`)

## Description
Ensure that data stored on your Google Cloud Filestore instances is encrypted at rest with Customer-Managed Encryption Keys (CMEK) instead of Google-managed encryption keys. CMEKs provide greater control over the encryption and decryption process, enabling you to meet stringent compliance requirements.

## Secure Mitigation
Re-create your Filestore instances with Customer-Managed Encryption Keys using Cloud KMS. Configure a key ring and CMK in Cloud KMS, then specify the key when creating the instance using the '--kms-key' flag or through the console.

