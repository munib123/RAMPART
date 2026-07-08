# Vulnerability: Azure VMSS Public IP Not Assigned
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vmss-public-ip-disabled.yaml`)

## Description
Ensure that instances running within your Microsoft Azure virtual machine scale set (VMSS) are not configured with public IP addresses. Assigning public IP addresses to individual VMSS instances increases attack surface, making it harder to manage and secure the environment.

## Secure Mitigation
Configure your VMSS to disable public IP address assignments to its instances. Ensure that all networking is handled through internal networking resources.

