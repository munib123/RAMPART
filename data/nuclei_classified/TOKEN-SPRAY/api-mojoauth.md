# Vulnerability: MojoAuth API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-mojoauth.yaml`)

## Description
Secure and modern passwordless authentication platform

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.mojoauth.com/token/jwks HTTP/1.1
Host: api.mojoauth.com
X-API-Key: {{token}}
```

