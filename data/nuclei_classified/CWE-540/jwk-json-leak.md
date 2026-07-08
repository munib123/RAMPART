# Vulnerability: JSON Web Key File - Exposure
**Classification:** CWE-540
**Source:** Nuclei Template (`jwk-json-leak.yaml`)

## Description
Searches for JSON Web Key (JWK) file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/jwks.json
GET {{BaseURL}}/.well-known/jwks
GET {{BaseURL}}/.well-known/openid-configuration/jwks.json
GET {{BaseURL}}/.well-known/openid-configuration/jwks
GET {{BaseURL}}/jwks.json
GET {{BaseURL}}/jwks
```

