# Vulnerability: Archibus Web Central Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`archibus-webcentral-panel.yaml`)

## Description
Archibus Web Central login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/archibus/login.axvw
GET {{BaseURL}}/archibus/schema/ab-core/views/sign-in/ab-sign-in.jsp
```

