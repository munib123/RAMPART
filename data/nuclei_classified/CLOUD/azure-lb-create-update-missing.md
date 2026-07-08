# Vulnerability: Azure Load Balancer Create or Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-lb-create-update-missing.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Create or Update Load Balancer" events are triggered within your Microsoft Azure cloud account. Activity log alerts get triggered when a new activity log event that matches the condition specified in the alert configuration occurs. For this conformity rule, the matched condition is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Create or Update Load Balancer (loadBalancers)'".

## Secure Mitigation
Configure Azure activity log alerts to include events for "Create or Update Load Balancer" with proper conditions to ensure compliance and operational awareness.

