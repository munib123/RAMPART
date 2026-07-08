# Vulnerability: Frappe Helpdesk Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`frappe-helpdesk-panel.yaml`)

## Description
Frappe Helpdesk products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/helpdesk/login
```

