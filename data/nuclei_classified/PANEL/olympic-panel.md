# Vulnerability: OLYMPIC Banking System Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`olympic-panel.yaml`)

## Description
OLYMPIC Banking System was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Connect.do
GET {{BaseURL}}/javaScript/responsive/portal.js
```

