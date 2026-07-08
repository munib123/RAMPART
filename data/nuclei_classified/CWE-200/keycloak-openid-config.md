# Vulnerability: Keycloak OpenID Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`keycloak-openid-config.yaml`)

## Description
Keycloak Openid configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/openid-configuration
GET {{BaseURL}}/auth/realms/master/.well-known/openid-configuration
```

