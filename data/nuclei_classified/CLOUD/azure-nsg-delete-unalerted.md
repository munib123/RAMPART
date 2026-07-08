# Vulnerability: Azure Network Security Group Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-delete-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is used to detect "Delete Network Security Group" events in your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the condition used is 'Whenever the Administrative Activity Log "Delete Network Security Group (networkSecurityGroups)" has "any" level, with "any" status and event is initiated by "any"'.

## Secure Mitigation
Configure alert rules to monitor and notify on "Delete Network Security Group" events by setting the alert condition to "Microsoft.Network/networkSecurityGroups/delete" and ensuring that an action group is attached to manage notifications.

