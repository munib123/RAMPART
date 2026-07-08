# Vulnerability: Azure NSG Rule Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-rule-delete-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is used to detect "Delete Network Security Group Rule" events in your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the condition used is 'Whenever the Administrative Activity Log "Delete Security Rule (networkSecurityGroups/securityRules)" has "any" level with "any" status and event is initiated by "any"'.

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Delete Network Security Group Rule" events by setting the alert condition to "Microsoft.Network/networkSecurityGroups/securityRules/delete" and ensuring that an action group is attached to manage notifications.

