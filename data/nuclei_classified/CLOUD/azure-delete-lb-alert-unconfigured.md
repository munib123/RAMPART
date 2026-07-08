# Vulnerability: Azure Delete Load Balancer Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-delete-lb-alert-unconfigured.yaml`)

## Description
Ensure that a Microsoft Azure activity log alert is fired whenever a "Delete Load Balancer" event is triggered within your cloud account. An Azure activity log alert fires each time the action event that matches the condition specified in the alert configuration is triggered. The alert condition that this conformity rule searches for is "Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete Load Balancer (loadBalancers)'".

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Delete Load Balancer" events by setting the alert condition to "Microsoft.Network/loadBalancers/delete" and attaching an action group for notifications.

