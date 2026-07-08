# Vulnerability: Vaultwarden Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`vaultwarden-panel.yaml`)

## Description
Vaultwarden products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login
```

