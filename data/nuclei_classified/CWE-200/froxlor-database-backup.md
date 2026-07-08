# Vulnerability: Froxlor Server Management Backup File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`froxlor-database-backup.yaml`)

## Description
Froxlor Server Management backup file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/froxlor.sql
```

