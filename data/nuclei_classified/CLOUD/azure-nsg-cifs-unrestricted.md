# Vulnerability: Unrestricted CIFS Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-cifs-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted access on TCP port 445, used by Common Internet File System (CIFS), to prevent unauthorized access.

## Secure Mitigation
Modify NSG rules to restrict access on TCP port 445. Only allow known IPs, and consider implementing stronger security measures for sensitive file transfers.

