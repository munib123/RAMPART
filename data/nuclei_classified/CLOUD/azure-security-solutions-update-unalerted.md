# Vulnerability: Azure Security Solutions Create/Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-security-solutions-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Create" or "Update Security Solution" events are triggered in your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the alert condition that this conformity rule searches for is 'Whenever the Security Activity Log "Create or Update Security Solutions (Microsoft.Security/securitySolutions)" has "any" level, with "any" status and event is initiated by "any".

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Create or Update Security Solution" events by setting the alert condition to "Microsoft.Security/securitySolutions/write" and ensuring that an action group is attached to manage notifications.

