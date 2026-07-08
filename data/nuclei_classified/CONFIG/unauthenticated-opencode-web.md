# Vulnerability: OpenCode Web - Unauthenticated Access
**Classification:** CONFIG
**Source:** Nuclei Template (`unauthenticated-opencode-web.yaml`)

## Description
Unauthenticated network access to the OpenCode web interface was detected. When the OpenCode web server is started without setting the OPENCODE_SERVER_PASSWORD environment variable, the server is completely unsecured.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Lw/session/
```

