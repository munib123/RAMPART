# Vulnerability: Frappe Framework - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`frappe-framework-detect.yaml`)

## Description
Frappe Framework products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/about
```

