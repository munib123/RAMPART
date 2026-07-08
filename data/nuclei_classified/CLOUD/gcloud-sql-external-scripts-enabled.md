# Vulnerability: External Scripts Enabled in SQL Server Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-external-scripts-enabled.yaml`)

## Description
Ensure that the external scripts enabled database flag is turned off for your Google Cloud SQL Server database instances in order to disable the execution of scripts with certain remote language extensions.

## Secure Mitigation
Disable the external scripts enabled flag in your SQL Server database instance configuration to enhance security and prevent potential misuse of the feature.

