# Vulnerability: Azure MySQL Database Create/Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-mysql-db-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Create/Update MySQL Database" events are triggered within your Microsoft Azure cloud account. The log alerts get triggered when a new activity log event that matches the condition specified in the alert configuration occurs. For this conformity rule, the matched condition is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Create/Update MySQL Database (servers/databases)'".

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Create or Update MySQL Database" events by setting the alert condition to "Microsoft.DBforMySQL/servers/databases/write" and ensuring that an action group is attached to manage notifications.

