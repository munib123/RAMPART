# Vulnerability: Azure Security Solution Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-security-solution-delete-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is used to detect "Delete Security Solution" events within your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the condition required is 'Whenever the Security Activity Log "Delete Security Solutions (Microsoft.Security/securitySolutions)" has "any" level, with "any" status and event is initiated by "any"'.

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Delete Security Solution" events by setting the alert condition to "Microsoft.Security/securitySolutions/delete" and ensuring that an action group is attached to manage notifications.

