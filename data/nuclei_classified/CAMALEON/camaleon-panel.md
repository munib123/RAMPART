# Vulnerability: Camaleon CMS Login - Panel
**Classification:** CAMALEON
**Source:** Nuclei Template (`camaleon-panel.yaml`)

## Description
Camaleon CMS admin login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
```

