# Vulnerability: Azure PostgreSQL Server Connection Throttling Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-postgres-connection-throttling-disabled.yaml`)

## Description
Ensure that "connection_throttling" server parameter is enabled for all PostgreSQL database servers provisioned within your Microsoft Azure cloud account. The "connection_throttling" parameter enables temporary connection throttling per IP address for too many invalid login failures.

## Secure Mitigation
Enable the "connection_throttling" server parameter on your Azure PostgreSQL servers to prevent excessive failed login attempts and mitigate potential attacks.

