# Vulnerability: FastAPI Docs Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fastapi-docs.yaml`)

## Description
FastAPI Docs panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/docs
GET {{BaseURL}}/redoc
GET {{BaseURL}}/openapi.json
```

