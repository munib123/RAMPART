# Vulnerability: Poste.io Admin Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`posteio-admin-panel.yaml`)

## Description
Poste.io login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

