# Vulnerability: Unrestricted FTP Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-ftp-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted access on TCP ports 20 and 21, used for File Transfer Protocol (FTP), to protect against unauthorized file transfers.

## Secure Mitigation
Update NSG rules to restrict FTP access by allowing only IP addresses that require FTP services on TCP ports 20 and 21.

