# Vulnerability: Azure Update Security Policy Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-security-policy-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is used to detect "Update Security Policy" events within your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the required alert condition is 'Whenever the Security Activity Log "Update security policy (Microsoft.Security/policies)" has "any" level, with "any" status and event is initiated by "any"'.

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Update Security Policy" events by setting the alert condition to "Microsoft.Security/policies/write" and ensuring that an action group is attached to manage notifications.

