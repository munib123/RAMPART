# Vulnerability: Huly Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`huly-panel.yaml`)

## Description
Huly products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login%3Acomponent%3ALoginApp
```

