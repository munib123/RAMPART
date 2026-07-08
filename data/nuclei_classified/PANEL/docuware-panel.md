# Vulnerability: DocuWare - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`docuware-panel.yaml`)

## Description
DocuWare panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/DocuWare/Identity/Account/Login
```

