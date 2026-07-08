# Vulnerability: Akuiteo Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`akuiteo-panel.yaml`)

## Description
Akuiteo products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/akuiteo.collabs/login/login.html
GET {{BaseURL}}/akuiteo/login.html/
```

