# Vulnerability: Ensure DNS Server Service is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`dns-server.yaml`)

## Description
The bind9 package provides a DNS server for name resolution services.Running a DNS server on systems not designated for that purpose may expose them to unnecessary risks.

## Secure Mitigation
- Ensure the `bind9` package is not installed unless explicitly required.
- To remove the package, run: sudo apt-get remove bind9 -y

