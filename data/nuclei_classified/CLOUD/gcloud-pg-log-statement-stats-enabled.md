# Vulnerability: Log Statement Stats Enabled in PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pg-log-statement-stats-enabled.yaml`)

## Description
Ensure that the "log_statement_stats" database flag is disabled for your Google Cloud PostgreSQL database instances in order to avoid performance issues caused by excessive logging. The "log_statement_stats" configuration flag controls the inclusion of end-to-end performance statistics within PostgreSQL logs for each SQL query.

## Secure Mitigation
Disable the "log_statement_stats" flag in your PostgreSQL database instance configuration to prevent performance issues caused by excessive logging.

