# Vulnerability: Veeam Backup Enterprise Manager Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`veeam-backup-manager-login.yaml`)

## Description
Veeam Backup Enterprise Manager Login

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.aspx
```

