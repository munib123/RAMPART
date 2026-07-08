# Vulnerability: Log Connections Disabled for PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-sql-log-connections-disabled.yaml`)

## Description
Ensure that the "log_connections" database flag is enabled for your Google Cloud PostgreSQL database instances. The "log_connections" flag causes each attempted connection to the database instance to be logged, including successful client authentication requests. This flag helps with monitoring and auditing database access. Only PostgreSQL database administrators can change this parameter at session start, and it cannot be changed after the session starts.

## Secure Mitigation
Enable the "log_connections" database flag for your PostgreSQL instances in Google Cloud. This can be done by updating the instance settings and applying the change.

