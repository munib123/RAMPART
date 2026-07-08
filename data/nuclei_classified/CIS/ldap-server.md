# Vulnerability: Ensure LDAP Server Service is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`ldap-server.yaml`)

## Description
The slapd package provides the OpenLDAP server, which manages directory and identity services. If not explicitly required, having this service installed unnecessarily increases the system’s attack surface.

## Secure Mitigation
- Run: sudo apt-get remove slapd -y
- This removes the LDAP server package to reduce the system’s attack surface.

