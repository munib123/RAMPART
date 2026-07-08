# Vulnerability: Ensure dnsmasq Service is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`dnsmasq-service.yaml`)

## Description
The dnsmasq package provides lightweight DNS, DHCP, and TFTP services. If not explicitly required, its presence may expose unnecessary services and increase security risks.

## Secure Mitigation
- Ensure the `dnsmasq` package is not installed unless explicitly required.
- To remove the package, run: sudo apt-get remove dnsmasq -y

