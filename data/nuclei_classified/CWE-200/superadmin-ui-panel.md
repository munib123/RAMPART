# Vulnerability: SuperAdmin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`superadmin-ui-panel.yaml`)

## Description
SuperAdmin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login
```

