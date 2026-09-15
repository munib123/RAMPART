# Nuclei Template: SFTP Configuration File - Credentials Exposure
**Template ID:** sftp-credentials-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`sftp-credentials-exposure.yaml`)

## Vulnerability Information & PoC

## Description
SFTP configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/sftp-config.json
GET {{BaseURL}}/ftpsync.settings
```

## References
- https://blog.sucuri.net/2012/11/psa-sftpftp-password-exposure-via-sftp-config-json.html
- https://www.acunetix.com/vulnerabilities/web/sftp-ftp-credentials-exposure/
- https://codexns.io/products/sftp_for_sublime/settings
