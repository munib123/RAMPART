# Vulnerability: Log Checkpoints Disabled in PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-log-checkpoints-disabled.yaml`)

## Description
Ensure that the "log_checkpoints" database flag is enabled for your Google Cloud PostgreSQL database instances. The "log_checkpoints" flag allows checkpoints and restart points to be logged and included within the PostgreSQL server log.

## Secure Mitigation
Enable the "log_checkpoints" flag for PostgreSQL database instances to ensure logging of checkpoints and restart points for better observability.

