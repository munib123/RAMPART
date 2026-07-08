# Vulnerability: Apache StreamPipes - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-streampipes-detect.yaml`)

## Description
Checks for the presence of Apache StreamPipes by looking in the body or matching the favicon hash.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/streampipes-backend/api/openapi.json
GET {{BaseURL}}/assets/img/favicon/favicon.ico
GET {{BaseURL}}
```

