# Vulnerability: Azure Virtual Machine Power Off Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-poweroff-unalerted.yaml`)

## Description
Ensure that a Microsoft Azure activity log alert is fired whenever a "Power Off Virtual Machine" event is triggered within your cloud account. An Azure activity log alert fires each time the action event that matches the condition defined in the alert configuration is triggered. The alert condition that this conformity rule checks for is `Whenever the Administrative Activity Log "Power Off Virtual Machine (Microsoft.Compute/virtualMachines)" has "any" Event level, with "any" Status and Event initiated by "any"`

## Secure Mitigation
Configure the activity log alert to trigger on the event "Microsoft.Compute/virtualMachines/powerOff/action". Ensure the alert condition includes any event level, status, and initiator to capture all related events.

