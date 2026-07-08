# Vulnerability: PostgreSQL Log Checkpoints Flag Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-postgresql-log-checkpoints-disabled.yaml`)

## Description
Ensure that the "log_checkpoints" database flag is enabled for all PostgreSQL database instances available within your Google Cloud Platform (GCP) account. The "log_checkpoints" flag allows checkpoints and restart points to be logged in the PostgreSQL server log. By default, this flag is disabled, and enabling it ensures better tracking and debugging of database operations.

## Secure Mitigation
Enable the "log_checkpoints" flag for all PostgreSQL database instances by updating the database configuration using the Google Cloud Console or gcloud CLI.

