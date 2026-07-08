# Vulnerability: Automatic Storage Increase Limit Not Configured for Cloud SQL
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-auto-storage-limit-not-configured.yaml`)

## Description
Ensure that an optimal limit is configured for the Automatic Storage Increase feature within your Cloud SQL database instance settings to avoid unexpected charges on your Google Cloud bill. Having no limit or an excessively high limit for this feature can lead to unplanned costs.

## Secure Mitigation
Configure an appropriate limit for the Automatic Storage Increase feature in your Cloud SQL database instance settings to control costs and maintain predictability.

