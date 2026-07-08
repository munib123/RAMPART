# Vulnerability: FTP Credentials Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`ftp-credentials-exposure.yaml`)

## Description
FTP credentials were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ftpsync.settings
```

