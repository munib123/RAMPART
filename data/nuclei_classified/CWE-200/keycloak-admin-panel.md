# Vulnerability: Keycloak Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`keycloak-admin-panel.yaml`)

## Description
Keycloak admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/auth/admin
GET {{BaseURL}}/auth/admin/master/console/
```

