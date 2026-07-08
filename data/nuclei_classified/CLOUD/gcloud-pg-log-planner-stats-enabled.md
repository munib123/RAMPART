# Vulnerability: Log Planner Stats Enabled in PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pg-log-planner-stats-enabled.yaml`)

## Description
Ensure that the log_planner_stats database flag is disabled for your Google Cloud PostgreSQL database instances in order to avoid performance issues caused by excessive logging. The log_planner_stats flag controls the inclusion of PostgreSQL planner performance statistics in the PostgreSQL logs for each query.

## Secure Mitigation
Disable the log_planner_stats flag in your PostgreSQL database instance configuration to prevent performance issues caused by excessive logging.

