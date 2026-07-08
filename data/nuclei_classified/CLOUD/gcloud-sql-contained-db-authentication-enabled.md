# Vulnerability: Contained Database Authentication Enabled in SQL Server Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-contained-db-authentication-enabled.yaml`)

## Description
Ensure that the "contained database authentication" database flag is disabled for your Google Cloud SQL Server database instances. This flag, when enabled, allows databases to contain their authentication and can potentially lead to security vulnerabilities.

## Secure Mitigation
Disable the "contained database authentication" flag in your SQL Server database instance configuration to enhance security and enforce centralized authentication.

