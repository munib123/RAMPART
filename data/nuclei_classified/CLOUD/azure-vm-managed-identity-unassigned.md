# Vulnerability: Azure VM Managed Identity Not Assigned
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-managed-identity-unassigned.yaml`)

## Description
Ensure that your Microsoft Azure virtual machines (VMs) have system-assigned managed identities enabled in order to allow secure virtual machine access to Azure resources such as key vaults and storage accounts.

## Secure Mitigation
Enable system-assigned managed identities on all Azure VMs to ensure secure access to other Azure services.

