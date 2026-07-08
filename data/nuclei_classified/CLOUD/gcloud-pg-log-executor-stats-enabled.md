# Vulnerability: Log Executor Stats Enabled in PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pg-log-executor-stats-enabled.yaml`)

## Description
Ensure that the log_executor_stats database flag is turned off for your Google Cloud PostgreSQL database instances in order to avoid performance issues caused by excessive logging. The log_executor_stats flag enables a crude profiling method for logging PostgreSQL executor performance statistics. The PostgreSQL executor is responsible for executing the plan handed over by the PostgreSQL planner/optimizer. The task of the PostgreSQL planner/optimizer is to create an optimal execution plan.

## Secure Mitigation
Disable the log_executor_stats flag in your PostgreSQL database instance configuration to prevent performance issues caused by excessive logging.

