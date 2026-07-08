# Vulnerability: SFTP Configuration File - Credentials Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`sftp-credentials-exposure.yaml`)

## Description
SFTP configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sftp-config.json
GET {{BaseURL}}/ftpsync.settings
```

