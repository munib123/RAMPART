# Vulnerability: Azure SQL Database Rename Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-sql-database-rename-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Rename Azure SQL Database" events are triggered within your Microsoft Azure cloud account. Activity log alerts get triggered when a new activity log event that matches the condition specified in the alert configuration occurs. For this conformity rule, the matched condition is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Rename Azure SQL Database (servers/databases)'".

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Rename Azure SQL Database" events by setting the alert condition to "Microsoft.Sql/servers/databases/move/action" and ensuring that an action group is attached to manage notifications.

