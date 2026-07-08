# Vulnerability: Detect OpenID Connect provider
**Classification:** TECH
**Source:** Nuclei Template (`oidc-detect.yaml`)

## Description
Detects OpenID Connect providers. See https://en.wikipedia.org/wiki/OpenID_Connect

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/openid-configuration
```

