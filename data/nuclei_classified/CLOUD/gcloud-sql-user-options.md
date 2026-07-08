# Vulnerability: User Options Flag Enabled in Google Cloud SQL Server Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-user-options.yaml`)

## Description
Checks if the "user options" database flag is configured for Google Cloud SQL Server instances, which can define global defaults for all database users.

## Secure Mitigation
Disable the "user options" database flag for your Google Cloud SQL Server instances to avoid global defaults for all database users.

