# Vulnerability: Log Parser Stats Enabled in PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pg-log-parser-stats-enabled.yaml`)

## Description
Ensure that the "log_parser_stats" database flag is turned off for your Google Cloud PostgreSQL database instances in order to avoid performance issues caused by excessive logging. The PostgreSQL planner (PostgreSQL optimizer) is responsible for parsing and verifying the syntax of each query received by the database server. If the syntax is correct, a parse tree is built up; otherwise, an error is generated. The "log_parser_stats" flag controls the inclusion of parser performance statistics within PostgreSQL logs for each query made to the database.

## Secure Mitigation
Disable the "log_parser_stats" flag in your PostgreSQL database instance configuration to prevent performance issues caused by excessive logging.

