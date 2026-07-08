# Vulnerability: Azure PostgreSQL Database Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-postgresql-db-delete-unalerted.yaml`)

## Description
Ensure that a Microsoft Azure activity log alert is fired whenever a “Delete PostgreSQL Database” event is triggered within your cloud account. An Azure activity log alert fires each time the action event that matches the condition specified in the alert configuration is triggered. The alert condition that this conformity rule checks for is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete PostgreSQL Database (Microsoft.DBforPostgreSQL/servers/databases)'".

## Secure Mitigation
Configure alert rules to fire when events with the operation name "Microsoft.DBforPostgreSQL/servers/databases/delete" occur, ensuring these critical events are monitored effectively.

