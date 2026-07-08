# Vulnerability: ReDoc API Docs - Detect
**Classification:** API
**Source:** Nuclei Template (`redoc-api-docs.yaml`)

## Description
ReDoc API documentation interface is available without authentication, potentially exposing information about the API endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/redoc
GET {{BaseURL}}/docs
GET {{BaseURL}}/api/docs
GET {{BaseURL}}/openapi
```

