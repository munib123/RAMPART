# Vulnerability: Homer Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`homer-panel.yaml`)

## Description
A simple static homepage was discovered

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.html
```

