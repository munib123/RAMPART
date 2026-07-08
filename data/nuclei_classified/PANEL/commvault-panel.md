# Vulnerability: Commvault Web Console Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`commvault-panel.yaml`)

## Description
Commvault web console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/commandcenter/login/preSso.jsp
```

