# Vulnerability: Traefik API - enabled
**Classification:** TRAEFIK
**Source:** Nuclei Template (`traefik-api-enabled.yaml`)

## Description
Traefik API is publicly accessible.It could expose sensitive routing, middleware, and service configuration details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/rawdata
GET {{BaseURL}}/api/http/routers
```

