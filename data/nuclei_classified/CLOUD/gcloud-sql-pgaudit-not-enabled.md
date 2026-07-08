# Vulnerability: pgAudit Flags Not Enabled for PostgreSQL Instances in Cloud SQL
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-pgaudit-not-enabled.yaml`)

## Description
Ensure that the "cloudsql.enable_pgaudit" and "pgaudit.log" database flags are enabled for your Google Cloud PostgreSQL server instances to enable database auditing. These configurations are crucial for compliance with government, financial, and ISO certifications.

## Secure Mitigation
Configure your PostgreSQL instances with the "cloudsql.enable_pgaudit" flag set to "on" and the "pgaudit.log" flag set to "all". These settings enable enhanced auditing capabilities.

