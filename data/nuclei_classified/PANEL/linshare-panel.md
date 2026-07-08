# Vulnerability: LinShare Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`linshare-panel.yaml`)

## Description
LinShare login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
GET {{BaseURL}}/new/login
```

