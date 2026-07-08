# Vulnerability: Azure Policy Assignment Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-policy-assignment-delete-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is used to detect "Delete Policy Assignment" events within your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the condition used is 'Whenever the Policy Activity Log "Delete policy assignment (policyAssignments)" has "any" level, with "any" status and event is initiated by "any"'.

## Secure Mitigation
Configure alert rules to monitor and notify on "Delete Policy Assignment" events by setting the alert condition to "Microsoft.Authorization/policyAssignments/delete" and ensuring that an action group is attached for notifications.

