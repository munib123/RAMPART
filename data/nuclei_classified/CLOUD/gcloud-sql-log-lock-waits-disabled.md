# Vulnerability: Log Lock Waits Flag Disabled for PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-log-lock-waits-disabled.yaml`)

## Description
Ensure that the "log_lock_waits" database flag is enabled for all your Google Cloud PostgreSQL database instances to improve database performance monitoring and troubleshooting.

## Secure Mitigation
Enable the "log_lock_waits" database flag for all PostgreSQL database instances in your Google Cloud environment. This ensures better monitoring and identification of lock wait issues.

