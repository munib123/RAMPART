# Vulnerability: Azure VMSS Instance Termination Notifications Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vmss-termination-notif-disabled.yaml`)

## Description
Ensure that your Microsoft Azure virtual machine scale sets are configured to receive instance termination notifications through the Azure Metadata service and have a predefined delay timeout configured for the "Terminate" operation (event). The termination notifications are delivered through Scheduled Events, an Azure Metadata feature which sends termination notifications, and can also be used to delay impactful operations such as reboots and redeployments. The delay associated with the "Terminate" event will depend on the delay limit specified in the VM scale set model configuration.

## Secure Mitigation
Configure the termination notification feature for all your Azure VM scale sets to receive proper alerts and set a reasonable delay for the termination events.

