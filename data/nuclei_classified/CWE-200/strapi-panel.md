# Vulnerability: Strapi Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`strapi-panel.yaml`)

## Description
Strapi login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/auth/login
GET {{BaseURL}}/admin/plugins/users-permissions/auth/login
```

