# Vulnerability: Unrestricted SSH Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-ssh-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted access on TCP port 22, used for Secure Shell (SSH), to prevent unauthorized access and potential breaches.

## Secure Mitigation
Modify NSG rules to restrict SSH access by allowing only specific, trusted IP addresses to connect on TCP port 22.

