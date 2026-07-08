# Vulnerability: OpenCart Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opencart-panel.yaml`)

## Description
OpenCart login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin
GET {{BaseURL}}/index.php?route=account/login
```

