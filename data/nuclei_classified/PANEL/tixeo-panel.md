# Vulnerability: Tixeo Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`tixeo-panel.yaml`)

## Description
Tixeo login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/meet/services/json/v1/settings
GET {{BaseURL}}/meet/login.html
GET {{BaseURL}}/meet/
```

