# Vulnerability: Ensure LDAP Client is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`ldap-client.yaml`)

## Description
The ldap-utils package provides LDAP client utilities that allow systems to query and interact with LDAP directories.If not explicitly required, it should be removed to minimize the system’s attack surface and reduce security risks.

## Secure Mitigation
- Ensure the ldap-utils package is not installed unless explicitly required.
- To remove the package, run: sudo apt-get remove ldap-utils -y

