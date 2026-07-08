# Vulnerability: TeslaMate - Unauthenticated Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`teslamate-unauth-access.yaml`)

## Description
A misconfig in Teslamate allows unauthorized access to /settings endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/settings
```

