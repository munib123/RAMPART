# Vulnerability: Web Transfer Client Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`webtransfer-client-panel.yaml`)

## Description
Progress Web Transfer Client login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ThinClient/WTM/public/index.html
```

