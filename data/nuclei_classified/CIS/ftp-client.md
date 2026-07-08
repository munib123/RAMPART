# Vulnerability: Ensure FTP Client is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`ftp-client.yaml`)

## Description
FTP clients such as ftp and tnftp use an unencrypted protocol that exposes sensitive data during transmission.These packages should only be installed when explicitly required, as their presence increases security risk.

## Secure Mitigation
- Ensure FTP client packages are not installed unless explicitly required.
- To remove them, run: sudo apt-get remove ftp tnftp -y

