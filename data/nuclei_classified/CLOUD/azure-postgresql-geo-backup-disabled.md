# Vulnerability: Azure PostgreSQL Geo-Redundant Backup Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-postgresql-geo-backup-disabled.yaml`)

## Description
Ensure that your Microsoft Azure PostgreSQL database servers have geo-redundant backups enabled, to allow you to restore your PostgreSQL servers to a different Azure region in the event of a regional outage or a disaster.

## Secure Mitigation
Enable geo-redundant backups in the Azure portal or use Azure CLI to update your PostgreSQL server's backup configuration to enable geo-redundancy.

