# Vulnerability: PostgREST API Server  - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`postrest-api-exposure.yaml`)

## Description
PostgREST API Server was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

