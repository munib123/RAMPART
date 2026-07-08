# Vulnerability: Strapi Admin - Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`strapi-admin-installer.yaml`)

## Description
Strapi Admin Registration enabled was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

