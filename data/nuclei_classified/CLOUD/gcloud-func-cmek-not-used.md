# Vulnerability: No Customer-Managed Encryption Keys in Google Cloud Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-cmek-not-used.yaml`)

## Description
Ensure that your Google Cloud functions use Customer-Managed Encryption Keys (CMEK) instead of Google-managed encryption keys to encrypt data at rest. CMEKs provide greater control over the encryption and decryption process, enabling you to meet stringent compliance requirements.

## Secure Mitigation
Configure your Google Cloud functions to use Customer-Managed Encryption Keys (CMEK) to ensure data encryption at rest is managed according to your compliance and security requirements.

