# Vulnerability: BigQuery Dataset Encryption with Customer-Managed Encryption Keys Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-bigquery-cmek-not-enabled.yaml`)

## Description
Ensure that all your Google Cloud BigQuery datasets are encrypted using Customer-Managed Encryption Keys (CMEKs) in order to have a more granular control over the dataset encryption/decryption process. Datasets not encrypted with CMEKs may expose sensitive data to higher risks.

## Secure Mitigation
Update the encryption configuration of your BigQuery datasets to use Customer-Managed Encryption Keys. This can be done by setting the 'defaultEncryptionConfiguration' property of each dataset to use a 'kmsKeyName' that you manage.

