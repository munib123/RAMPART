# Vulnerability: Espec Web Controller - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`espec-web-controller-panel.yaml`)

## Description
Espec Web Controller panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/version
```

