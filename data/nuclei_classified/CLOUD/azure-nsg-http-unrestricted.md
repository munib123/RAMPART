# Vulnerability: Unrestricted TCP Port 80 Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-http-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted access on TCP port 80 to protect against attackers using brute force methods to gain access to Azure virtual machines associated with these NSGs.

## Secure Mitigation
Modify NSG rules to restrict access on TCP port 80. Ensure that only known IPs are allowed, or implement additional authentication methods to protect against unauthorized access.

