# Vulnerability: Quilium Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`quilium-panel.yaml`)

## Description
Quilium CMS Login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/en/login
```

