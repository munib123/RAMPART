# Vulnerability: Keycloak Admin Console Configuration Disclosure
**Classification:** KEYCLOAK
**Source:** Nuclei Template (`keycloak-admin-console-config.yaml`)

## Description
Detected Keycloak admin console configuration was exposing realm name, client ID, SSL requirements, and authentication server URL enabling reconnaissance and targeted authentication attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/master/console/config
GET {{BaseURL}}/admin/main/console/config
GET {{BaseURL}}/auth/admin/master/console/config
GET {{BaseURL}}/auth/admin/main/console/config
```

