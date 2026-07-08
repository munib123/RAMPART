# Vulnerability: Ensure Message Access Server Service is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`message-access-server.yaml`)

## Description
The dovecot-imapd package provides the Dovecot IMAP server, which allows users to remotely access email stored on the system. If not explicitly required, having this service installed unnecessarily increases the system's attack surface and could expose it to potential remote exploits. To maintain a secure system, IMAP services should only be installed and enabled when there is a clear business requirement.

## Secure Mitigation
- Ensure the `slapd` package is not installed unless explicitly required.
- To remove the package, run: sudo apt-get remove slapd -y

