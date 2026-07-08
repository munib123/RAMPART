# Vulnerability: Authentik Panel - Detect
**Classification:** AUTHENTIK
**Source:** Nuclei Template (`authentik-panel.yaml`)

## Description
An Authentik search engine was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/static/dist/assets/icons/icon.png
```

