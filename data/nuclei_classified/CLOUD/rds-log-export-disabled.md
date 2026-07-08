# Vulnerability: RDS Log Exports - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-log-export-disabled.yaml`)

## Description
Ensure that your Amazon RDS database instances have the Log Exports feature enabled in order to publish database log events directly to CloudWatch Logs.

## Secure Mitigation
Enable RDS log exports in the AWS Management Console or via CLI/API by configuring the desired logs (e.g., slow query, general, error logs) for export to CloudWatch.

