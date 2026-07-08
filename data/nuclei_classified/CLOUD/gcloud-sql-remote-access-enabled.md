# Vulnerability: Remote Access Enabled for SQL Server Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-remote-access-enabled.yaml`)

## Description
Ensure that the "remote access" database flag is turned off for your Google Cloud SQL Server database instances. This prevents the execution of stored procedures from local or remote servers on which your SQL Server instances are running, improving security and compliance.

## Secure Mitigation
Disable the "remote access" database flag for all SQL Server database instances in Google Cloud Platform. Update the database configuration settings to ensure the flag is turned off.

