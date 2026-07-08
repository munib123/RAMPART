# Vulnerability: YunoHost Admin Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`yunohost-admin-panel.yaml`)

## Description
YunoHost Admin panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/yunohost/admin
```

