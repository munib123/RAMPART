# Vulnerability: Azure MySQL Database Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-db-mysql-delete-unalerted.yaml`)

## Description
Ensure that a Microsoft Azure activity log alert is fired whenever a "Delete MySQL Database" event is triggered within your cloud account. An Azure activity log alert fires each time the action event that matches the condition specified in the alert configuration is triggered. The alert condition that this conformity rule checks for is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete MySQL Database (servers/databases)'"

## Secure Mitigation
Configure an activity log alert to fire on "Delete MySQL Database" events with the condition set to "Microsoft.DBforMySQL/servers/databases/delete" and ensure that an action group is attached to manage notifications.

