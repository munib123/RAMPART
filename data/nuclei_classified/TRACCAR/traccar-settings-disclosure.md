# Vulnerability: Traccar Server Settings - Disclosure
**Classification:** TRACCAR
**Source:** Nuclei Template (`traccar-settings-disclosure.yaml`)

## Description
Traccar exposes server settings at the /api/server endpoint without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/server
```

