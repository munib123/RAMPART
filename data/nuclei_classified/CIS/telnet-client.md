# Vulnerability: Ensure Telnet Client is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`telnet-client.yaml`)

## Description
The telnet and inetutils-telnet packages provide a Telnet client for remote access.Since Telnet uses unencrypted communication, these packages should not be installed to reduce the risk of credential theft and unauthorized access.

## Secure Mitigation
Ensure telnet and inetutils-telnet packages are not installed unless explicitly required.To remove them, run: sudo apt-get remove telnet inetutils-telnet -y

