# Vulnerability: Azure VM Microsoft Entra ID Authentication Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-entra-id-unenabled.yaml`)

## Description
Ensure that your Microsoft Azure virtual machines (VMs) are configured to use Microsoft Entra ID credentials for secure SSH/RDP access. Once enabled, you can use your corporate Microsoft Entra ID credentials to log in to your virtual machines, enforce Multi-Factor Authentication (MFA), or enable access via RBAC roles.

## Secure Mitigation
Ensure the Microsoft Entra ID authentication extensions, "AADLoginForWindows" or "AADLoginForLinux", are installed and enabled on your Azure VMs for secure access management.

