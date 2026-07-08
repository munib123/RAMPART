# Vulnerability: Unrestricted RDP Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-rdp-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted access on TCP port 3389, used for Remote Desktop Protocol (RDP), to prevent unauthorized remote access.

## Secure Mitigation
Configure NSG rules to restrict RDP access to only trusted IP addresses. Consider using VPNs or other secure methods for remote access.

