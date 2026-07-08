# Vulnerability: Enable Object Encryption with Customer-Managed Keys for Cloud Storage Buckets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-object-encryption-cmk-not-enabled.yaml`)

## Description
Ensure that your Google Cloud Storage data is encrypted at rest using Customer-Managed Keys (CMKs) to maintain full control over your data encryption and decryption processes. CMKs can be managed with the Cloud Key Management Service (Cloud KMS).

## Secure Mitigation
Configure your Cloud Storage buckets to use Customer-Managed Keys (CMKs) for encryption to enhance data security and comply with organizational policies.

