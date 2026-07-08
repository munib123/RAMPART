# Vulnerability: Filestore Instance Not Using On-Demand Backup
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-filestore-no-backups.yaml`)

## Description
Ensure that on-demand backup and restore functionality is in use for your Google Cloud Filestore instances to ensure data protection, disaster recovery, and regulatory compliance. The backup and restore process does not consume provisioned capacity and has no impact on the performance and availability of your Filestore applications.

## Secure Mitigation
Create on-demand backups for your Filestore instances using the 'gcloud filestore backups create' command or through the Google Cloud Console. Configure regular backup schedules to ensure point-in-time recovery capabilities.

