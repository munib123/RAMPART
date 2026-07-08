# Vulnerability: Public Swagger API - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`swagger-api.yaml`)

## Description
Public Swagger API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

