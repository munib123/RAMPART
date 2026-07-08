# Vulnerability: Azure PostgreSQL Log Duration Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-postgres-log-duration-disabled.yaml`)

## Description
Ensure that "log_duration" server parameter is enabled for all PostgreSQL database servers created in your Microsoft Azure cloud account. Once enabled, the "log_duration" parameter allows recording the duration of each completed PostgreSQL statement. Only users with administrative privileges can change this setting within Azure PostgreSQL server configuration. For database clients using extended query protocol, the duration of the "Parse", "Bind", and "Execute" steps is logged independently.

## Secure Mitigation
Enable the "log_duration" parameter in Azure PostgreSQL server configurations to ensure comprehensive logging of query durations for security and performance analysis.

