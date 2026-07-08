# Vulnerability: Azure Network Security Group Create/Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-create-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Create" or "Update Network Security Group" events are triggered within your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the alert condition that we search for is 'Whenever the Administrative Activity Log "Create or Update Network Security Group (Microsoft.Network/networkSecurityGroups)" has "any" level, with "any" status and event is initiated by "any"'.

## Secure Mitigation
Configure alert rules to monitor "Create" or "Update Network Security Group" events by setting the alert condition to "Microsoft.Network/networkSecurityGroups/write" and attaching an action group to handle notifications.

