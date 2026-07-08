# Vulnerability: Azure PostgreSQL Log Connections Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-postgres-log-connections-disabled.yaml`)

## Description
Ensure that "log_connections" server parameter is enabled for all PostgreSQL database servers available in your Microsoft Azure cloud account. The "log_connections" parameter allows each attempted connection to the database server to be logged, including successful client authentication requests. Only Azure users with administrative privileges can change this parameter at session start, and it cannot be changed during an access session.

## Secure Mitigation
Enable the "log_connections" server parameter for all Azure PostgreSQL servers to ensure that all connection attempts are logged, enhancing security monitoring capabilities.

