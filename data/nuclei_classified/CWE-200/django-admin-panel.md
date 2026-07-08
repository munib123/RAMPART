# Vulnerability: Python Django Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`django-admin-panel.yaml`)

## Description
Python Django admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login/
```

