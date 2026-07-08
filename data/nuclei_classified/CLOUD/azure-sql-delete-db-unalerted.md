# Vulnerability: Azure SQL Delete Database Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-sql-delete-db-unalerted.yaml`)

## Description
Ensure that a Microsoft Azure activity log alert is fired whenever a "Delete Azure SQL Database" event is triggered within your cloud account. An Azure activity log alert fires each time the action event that matches the condition specified in the alert configuration is triggered. The alert condition that this conformity rule searches for is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete Azure SQL Database (Microsoft.Sql/servers/databases)'".

## Secure Mitigation
Configure alert rules to monitor and notify on "Delete Azure SQL Database" events by setting the alert condition to "Microsoft.Sql/servers/databases/delete" and ensuring an action group is configured to handle the alert.

