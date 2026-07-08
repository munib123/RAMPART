# Vulnerability: Log Statement Flag Not Configured Properly for PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pg-log-statement-flag-not-configured.yaml`)

## Description
Ensure that the "log_statement" database flag configured for your Google Cloud PostgreSQL database instances has the appropriate value (logging level) in accordance with your organization's logging policy. The "log_statement" flag controls which SQL statements are logged, with valid values being: none, ddl, mod, and all.

## Secure Mitigation
Set the "log_statement" flag to the appropriate value (e.g., mod) based on your organization's logging policy to balance performance and logging requirements.

