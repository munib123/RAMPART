# Vulnerability: FTP Access Control Check
**Classification:** FTP
**Source:** Nuclei Template (`ftp-access-control-check.yaml`)

## Description
Ensure FTP access is restricted by configuring IP address filters. Without these restrictions, unauthorized networks could potentially access FTP services.

## Secure Mitigation
Set up IP address restrictions using IIS Manager:
- Open IIS Manager.
- Go to the FTP site → FTP IP Address and Domain Restrictions.
- Add the allowed IP addresses and configure suitable deny rules.

