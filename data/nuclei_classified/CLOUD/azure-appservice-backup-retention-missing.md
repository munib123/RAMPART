# Vulnerability: Azure App Service Backup Retention Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-appservice-backup-retention-missing.yaml`)

## Description
Ensure that your Microsoft Azure App Services applications have a sufficient daily backup retention period configured for scheduled backups, in order to follow security and regulatory requirements. Prior to running this rule by the Cloud Conformity engine, the backup retention period must be configured in the rule settings, on the Cloud Conformity account dashboard. A retention value of 0 will keep backup files indefinitely.

## Secure Mitigation
Configure the daily backup retention period for Azure App Services applications in the Cloud Conformity account dashboard to meet security and compliance requirements.

