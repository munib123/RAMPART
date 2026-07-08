# Vulnerability: Azure Virtual Machine Delete Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-delete-unalerted.yaml`)

## Description
Ensure that a Microsoft Azure activity log alert is fired whenever a "Delete Virtual Machine" event is triggered within your cloud account. An Azure activity log alert fires each time the action event that matches the condition specified in the alert configuration is triggered. The alert condition that this conformity rule searches for is `Whenever the Administrative Activity Log "Delete Virtual Machine (Microsoft.Compute/virtualMachines)" has "any" Event level, with "any" Status and Event initiated by "any"`.

## Secure Mitigation
Configure activity log alerts to fire on "Delete Virtual Machine" events by setting the alert condition to "Microsoft.Compute/virtualMachines/delete" and ensure that notifications are managed by an attached action group.

