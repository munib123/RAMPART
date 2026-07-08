# Vulnerability: Ensure DHCP Server Service is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`dhcp-server.yaml`)

## Description
The isc-dhcp-server package provides DHCP services for automatic IP address assignment.Running a DHCP server on non-designated systems may introduce security risks and unwanted network behavior.

## Secure Mitigation
- Ensure the isc-dhcp-server package is not installed unless explicitly required.
- To remove the package, run: sudo apt-get remove isc-dhcp-server -y

