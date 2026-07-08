# Vulnerability: Azure VM Create/Update Alert Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-create-update-unalerted.yaml`)

## Description
Ensure that an Azure activity log alert is fired whenever "Create Virtual Machine" or "Update Virtual Machine" events are triggered in your Microsoft Azure cloud account. Activity log alerts get triggered when a new activity log event that matches the condition specified in the alert configuration occurs. This rule is crucial as it monitors for any administrative activity log related to "Create or Update Virtual Machine".

## Secure Mitigation
Configure alert rules to fire on "Create or Update Virtual Machine" events by setting the alert condition to "Microsoft.Compute/virtualMachines/write" and ensuring that notifications are managed through an action group.

