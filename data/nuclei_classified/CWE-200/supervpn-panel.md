# Vulnerability: SuperVPN Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`supervpn-panel.yaml`)

## Description
SuperVPN login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login.html
```

