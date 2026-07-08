# Vulnerability: Automated Backups Not Enabled for Cloud SQL Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-backups-disabled.yaml`)

## Description
Ensure that automated (scheduled) backups are created for all Cloud SQL database instances available within your Google Cloud Platform (GCP) account, in order to protect against data deletion and/or data corruption.

## Secure Mitigation
Enable automated backups for all Cloud SQL database instances in your GCP account to ensure regular backups are taken to safeguard against data issues.

