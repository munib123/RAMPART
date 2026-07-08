# Vulnerability: Azure Virtual Machine Deallocate Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-deallocate-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Deallocate Virtual Machine" events are triggered within your Microsoft Azure cloud account. An Azure activity log alert is triggered when a new activity log event that matches the condition specified in the alert configuration occurs. For this conformity rule, the matched condition is `Whenever the Administrative Activity Log "Deallocate Virtual Machine (Microsoft.Compute/virtualMachines)" has "any" Event level, with "any" Status and Event initiated by "any"`.

## Secure Mitigation
Configure Azure activity log alerts to detect "Deallocate Virtual Machine" events by setting the alert condition to "Microsoft.Compute/virtualMachines/deallocate/action" and ensuring that alerts trigger notifications appropriately.

