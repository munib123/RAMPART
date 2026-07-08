# Vulnerability: Laravel Backpack Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`backpack-admin-panel.yaml`)

## Description
Laravel Backpack admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

