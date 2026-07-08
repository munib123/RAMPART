# Vulnerability: Monsta FTP - Detect
**Classification:** TECH
**Source:** Nuclei Template (`monsta-ftp-detect.yaml`)

## Description
Detects Monsta FTP web-based file manager interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

