# Vulnerability: Azure Policy Assignment Create Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-policy-assignment-create-alert-missing.yaml`)

## Description
Ensure that an Azure activity log alert is used to detect "Create Policy Assignment" events within your Microsoft Azure cloud account. Activity log alerts get activated when a new activity log event that matches the condition specified in the alert occurs. In this case, the condition used is 'Whenever the Policy Activity Log "Create policy assignment (policyAssignments)" has "any" level, with "any" status and event is initiated by "any"'.

## Secure Mitigation
Configure an Azure activity log alert for "Create Policy Assignment" events to ensure compliance and enhance security monitoring.

