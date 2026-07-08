# Vulnerability: Azure VM Boot Disk Not Encrypted
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-boot-disk-unencrypted.yaml`)

## Description
Ensure that your Microsoft Azure virtual machine (VM) boot volumes are encrypted using Azure Disk Encryption in order to meet security and compliance requirements. ADE encrypts the OS and data disks of Azure virtual machines (VMs) using the CPU via the DM-Crypt feature for Linux or the BitLocker feature for Windows. ADE is integrated with Azure Key Vault to help you control and manage the disk encryption keys and secrets. The boot (OS) volumes encryption and decryption is handled transparently and does not require any additional action from you, your Azure virtual machine, or your cloud application.

## Secure Mitigation
Enable Azure Disk Encryption for VM boot volumes using Azure Key Vault to manage encryption keys and ensure data security.

