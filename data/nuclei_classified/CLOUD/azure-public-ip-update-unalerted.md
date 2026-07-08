# Vulnerability: Azure Public IP Create/Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-public-ip-update-unalerted.yaml`)

## Description
Ensure that activity log alerts are used to detect "Create or Update Public IP Address" events within your Microsoft Azure cloud account. An activity log alert gets activated when a new activity log event that matches the condition specified in the alert occurs.

## Secure Mitigation
Ensure alert rules are properly configured to monitor and notify on "Create or Update Public IP Address" events by setting the alert condition to "Microsoft.Network/publicIPAddresses/write" and ensuring that an action group is attached to manage notifications.

