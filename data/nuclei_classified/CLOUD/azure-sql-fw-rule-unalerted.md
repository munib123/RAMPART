# Vulnerability: Azure SQL Server Firewall Rule Create/Update/Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-sql-fw-rule-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever “Create”, “Update” or “Delete SQL Server Firewall Rule” events are triggered in your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the condition required for the alert is 'Whenever the Administrative Activity Log "Create/Update/Delete server firewall rule (Microsoft.Sql/servers/firewallRules)" has "any" level, with "any" status and event is initiated by "any"'.

## Secure Mitigation
Configure activity log alerts to monitor "Create, Update, or Delete SQL Server Firewall Rule" events by setting the alert condition to "Microsoft.Sql/servers/firewallRules/write" and attaching an action group to handle notifications.

