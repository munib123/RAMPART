# Vulnerability: Cross DB Ownership Chaining Enabled in SQL Server Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-cross-db-ownership-chaining-enabled.yaml`)

## Description
Ensure that the "cross db ownership chaining" database flag is disabled for your Google Cloud SQL Server database instances. This flag, when enabled, can potentially introduce security risks by allowing cross-database access without explicit permissions.

## Secure Mitigation
Disable the "cross db ownership chaining" flag in your SQL Server database instance configuration to prevent unauthorized cross-database access.

