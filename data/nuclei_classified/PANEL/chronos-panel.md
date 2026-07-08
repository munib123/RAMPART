# Vulnerability: Chronos Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`chronos-panel.yaml`)

## Description
Chronos Login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/chronos.wsc/asparamlogin.html
```

