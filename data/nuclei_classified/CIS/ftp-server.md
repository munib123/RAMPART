# Vulnerability: Ensure FTP Server Service is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`ftp-server.yaml`)

## Description
The vsftpd package provides an FTP server for file transfer services.Since FTP is unencrypted and insecure, it should only be installed when explicitly required.

## Secure Mitigation
- Ensure the `vsftpd` package is not installed unless explicitly required.
- To remove the package, run: sudo apt-get remove vsftpd -y

