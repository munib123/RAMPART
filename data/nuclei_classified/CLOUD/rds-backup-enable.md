# Vulnerability: RDS Automated Backup Check
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-backup-enable.yaml`)

## Description
Ensure that your Amazon RDS database instances have automated backups enabled for point-in-time recovery.

## Secure Mitigation
Enable automated backups for RDS instances by setting the backup retention period to a value other than 0.

