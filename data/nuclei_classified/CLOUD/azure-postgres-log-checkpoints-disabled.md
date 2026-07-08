# Vulnerability: Azure PostgreSQL Flexible Server log_checkpoints Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-postgres-log-checkpoints-disabled.yaml`)

## Description
Ensure that "log_checkpoints" server parameter is enabled for all PostgreSQL flexible database servers available within your Microsoft Azure cloud account. The "log_checkpoints" parameter allows checkpoints and restart points to be logged in the Azure PostgreSQL server log.

## Secure Mitigation
Enable the "log_checkpoints" parameter for your Azure PostgreSQL flexible servers to ensure critical operational events are logged.

