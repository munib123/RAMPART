# Vulnerability: AMPPS Admin Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`ampps-admin-panel.yaml`)

## Description
An AMPPS Admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ampps-admin/index.php?act=login
```

