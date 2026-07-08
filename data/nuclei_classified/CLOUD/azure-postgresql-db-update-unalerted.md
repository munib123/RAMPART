# Vulnerability: Azure PostgreSQL Database Create/Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-postgresql-db-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever “Create/Update PostgreSQL Database” events are triggered within your Microsoft Azure cloud account. The log alerts get triggered when a new activity log event that matches the condition specified in the alert configuration occurs. For this conformity rule, the matched condition is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Create/Update PostgreSQL Database (servers/databases)'"

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Create or Update PostgreSQL Database" events by setting the alert condition to "Microsoft.DBforPostgreSQL/servers/databases/write" and ensuring that an action group is attached to manage notifications.

