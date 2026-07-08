# Vulnerability: Unrestricted Telnet Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-telnet-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted access on TCP port 23, used by Telnet, to prevent unauthorized command execution.

## Secure Mitigation
Modify NSG rules to restrict access on TCP port 23. Only allow access from secure, authenticated sources and consider using more secure alternatives like SSH.

