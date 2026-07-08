# Vulnerability: CrafterCMS Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`craftercms-panel.yaml`)

## Description
CrafterCMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/studio/login
```

