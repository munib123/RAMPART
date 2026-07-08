# Vulnerability: TemboSocial Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tembosocial-panel.yaml`)

## Description
TemboSocial Admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin.php
```

