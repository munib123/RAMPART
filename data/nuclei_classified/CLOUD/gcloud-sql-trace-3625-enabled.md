# Vulnerability: Trace Flag 3625 Enabled in SQL Server Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-trace-3625-enabled.yaml`)

## Description
Ensure that the 3625 trace flag is turned off for all your Google Cloud SQL Server database instances to follow security best practices. Trace flag 3625 controls the format of certain error messages, which may reveal sensitive information if enabled.

## Secure Mitigation
Disable the 3625 trace flag in your SQL Server database instance configuration to enhance security and protect sensitive information.

