# Vulnerability: WADL API - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wadl-api.yaml`)

## Description
WADL API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/application.wadl
GET {{BaseURL}}/application.wadl?detail=true
GET {{BaseURL}}/api/application.wadl
GET {{BaseURL}}/api/v1/application.wadl
GET {{BaseURL}}/api/v2/application.wadl
OPTIONS {{BaseURL}}
OPTIONS {{BaseURL}}/api/v1
OPTIONS {{BaseURL}}/api/v2
```

