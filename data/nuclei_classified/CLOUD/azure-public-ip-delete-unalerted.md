# Vulnerability: Azure Public IP Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-public-ip-delete-unalerted.yaml`)

## Description
Ensure that activity log alerts are used to detect "Delete Public IP Address" events within your Microsoft Azure cloud account. An activity log alert gets activated when a new activity log event that matches the condition specified in the alert occurs.

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Delete Public IP Address" events by setting the alert condition to "Microsoft.Network/publicIPAddresses/delete" and ensuring that an action group is attached to manage notifications.

