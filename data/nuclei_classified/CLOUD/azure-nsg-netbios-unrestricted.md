# Vulnerability: Unrestricted NetBIOS Access in Azure NSGs
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nsg-netbios-unrestricted.yaml`)

## Description
Ensure that Microsoft Azure network security groups (NSGs) do not allow unrestricted inbound access on TCP port 139 and UDP ports 137 and 138, used by NetBIOS, to protect against unauthorized network exploration and exploitation.

## Secure Mitigation
Update NSG rules to limit NetBIOS access to only necessary and secure sources, thereby enhancing the overall security posture of your network infrastructure.

