# Vulnerability: Pub/Sub Topics Not Encrypted with Customer-Managed Encryption Keys
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pubsub-cmek-disabled.yaml`)

## Description
Ensure that your Google Cloud Pub/Sub topics are encrypted using Customer-Managed Encryption Keys (CMEKs) to have full control over the data encryption and decryption process. Customer-Managed Encryption Keys (CMEKs) allow you to create and manage your own encryption keys with Cloud Key Management Service (Cloud KMS).

## Secure Mitigation
Configure your Pub/Sub topics to use Customer-Managed Encryption Keys (CMEKs) by specifying a Cloud KMS key during the topic creation or update process.

