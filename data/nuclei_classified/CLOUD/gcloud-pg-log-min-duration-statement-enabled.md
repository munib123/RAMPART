# Vulnerability: Log Min Duration Statement Enabled in PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pg-log-min-duration-statement-enabled.yaml`)

## Description
Ensure that the log_min_duration_statement database flag is set to -1 (i.e., disabled) for all your Google Cloud PostgreSQL database instances. The log_min_duration_statement flag controls the minimum execution time of a statement for it to be logged. Setting it to any value other than -1 can result in excessive logging and potential performance issues.

## Secure Mitigation
Set the log_min_duration_statement flag to -1 in your PostgreSQL database instance configuration to disable logging based on statement duration.

