# Vulnerability: BigQuery Datasets Not Encrypted with Customer-Managed Keys
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-bigquery-cmk-not-enabled.yaml`)

## Description
Ensure that the tables created for your Google Cloud BigQuery datasets are encrypted with Customer-Managed Keys (CMKs) to have more granular control over the data encryption/decryption process. Using CMKs allows you to create, rotate, manage, and destroy your own encryption keys using Google Cloud Key Management Service (Cloud KMS).

## Secure Mitigation
Configure BigQuery dataset tables to use Customer-Managed Keys (CMKs) for encryption. This can be done in the dataset settings where you specify the encryption key managed in Google Cloud KMS.

