# Vulnerability: Server Backup Manager SE Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`server-backup-login.yaml`)

## Description
Server Backup Manager SE login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.zul
```

