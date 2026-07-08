# Vulnerability: AWS RDS Backtrack - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-backtrack-disabled.yaml`)

## Description
Ensure that the Backtrack feature is enabled for your Amazon Aurora (with MySQL compatibility) database clusters in order to backtrack your clusters to a specific time, without using backups.

## Secure Mitigation
Enable Backtrack for the RDS instance through the AWS Management Console, CLI, or API, and configure the desired backtrack window to allow quick recovery.

