# Vulnerability: WS_FTP Server Web Transfer - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ws_ftp-server-web-transfer.yaml`)

## Description
WS_FTP Server Web Transfer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

