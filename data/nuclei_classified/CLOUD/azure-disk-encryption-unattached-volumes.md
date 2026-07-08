# Vulnerability: Azure Disk Encryption Not Enabled for Unattached Disk Volumes
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-disk-encryption-unattached-volumes.yaml`)

## Description
Ensure that your detached Microsoft Azure virtual machine (VM) disk volumes are encrypted using Azure Disk Encryption in order to meet security and compliance requirements. ADE encrypts the OS and data disks of Azure virtual machines (VMs) inside your VMs using the CPU via the DM-Crypt feature for Linux or the BitLocker feature for Windows. ADE is integrated with Azure Key Vault to help you control and manage the disk encryption keys and secrets. The unattached disk volumes encryption and decryption is handled transparently and does not require any additional action from you, your Azure virtual machine, or your application.

## Secure Mitigation
Encrypt all unattached disk volumes using Azure Disk Encryption integrated with Azure Key Vault to ensure data is protected even when disks are detached.

