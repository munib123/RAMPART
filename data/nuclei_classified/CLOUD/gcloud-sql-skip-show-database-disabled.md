# Vulnerability: Skip Show Database Flag Not Enabled for MySQL Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-skip-show-database-disabled.yaml`)

## Description
Ensure that the "skip_show_database" database flag is enabled for your Google Cloud MySQL database instances in order to prevent users from using the SHOW DATABASES statement if they don't have this privilege.

## Secure Mitigation
Enable the "skip_show_database" flag for MySQL database instances in Google Cloud. This can be configured in the database settings under the databaseFlags section or through the gcloud CLI.

