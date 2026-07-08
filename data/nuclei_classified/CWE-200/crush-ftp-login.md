# Vulnerability: CrushFTP WebInterface Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`crush-ftp-login.yaml`)

## Description
CrushFTP WebInterface login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/WebInterface/login.html
```

