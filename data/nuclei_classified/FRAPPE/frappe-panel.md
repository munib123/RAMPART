# Vulnerability: Frappe Panel - Detect
**Classification:** FRAPPE
**Source:** Nuclei Template (`frappe-panel.yaml`)

## Description
Frappe ERPNext Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login#login
```

