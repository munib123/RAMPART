# Vulnerability: Azure Network Security Group Rule Create/Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-rule-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Create" or "Update Network Security Group Rule" events are triggered within your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the alert condition required is 'Whenever the Administrative Activity Log "Create or Update Security Rule (networkSecurityGroups/securityRules)" has "any" level, with "any" status and event is initiated by "any"'.

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Create or Update Network Security Group Rule" events by setting the alert condition to "Microsoft.Network/networkSecurityGroups/securityRules/write" and ensuring that an action group is attached to manage notifications.

