# Vulnerability: Passbolt Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`passbolt-panel.yaml`)

## Description
Passbolt login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

