# Vulnerability: Log Hostname Flag Disabled for PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-postgresql-log-hostname-disabled.yaml`)

## Description
Ensure that the "log_hostname" database flag is enabled for your Google Cloud PostgreSQL database instances in order to assist with incident response and tracking usage in an environment utilizing dynamic IP addresses. There is a potential cost to server performance caused by hostname logging.

## Secure Mitigation
Enable the "log_hostname" database flag for all PostgreSQL database instances in your Google Cloud environment to ensure proper logging and traceability.

