# Vulnerability: Monstra Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`monstra-admin-panel.yaml`)

## Description
Monstra admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/index.php
```

