# Vulnerability: ConnectWise Server Backup Manager SE Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`connectwise-backup-manager.yaml`)

## Description
ConnectWise Server Backup Manager SE login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.zul
```

