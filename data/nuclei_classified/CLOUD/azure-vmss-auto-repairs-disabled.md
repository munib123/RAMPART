# Vulnerability: Azure VMSS Automatic Instance Repairs Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vmss-auto-repairs-disabled.yaml`)

## Description
Ensure that unhealthy virtual machine instances are automatically deleted from the scale sets and new ones are created, using the latest instance model settings. Automatic Instance Repairs feature relies on health checks performed for individual instances running in a scale set. These virtual machine instances can be configured to emit an application health status using the Azure Application Health extension or a load balancer health probe. If a VM instance is found to be unhealthy, as reported by the Application Health extension or by the associated load balancer health probe, then the scale set performs the repair action by deleting the unhealthy instance and creating a new one to replace it.

## Secure Mitigation
Enable the Automatic Instance Repairs feature for Azure VMSS to ensure high availability and resilience of your applications.

