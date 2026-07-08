# Vulnerability: ChromaDB - Unauthenticated API Exposure
**Classification:** CHROMADB
**Source:** Nuclei Template (`chroma-api-exposure.yaml`)

## Description
ChromaDB runs without authentication by default, exposing the API edpoint to anyone and allowing unauthorized access to read.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v2/tenants/default_tenant/databases/default_database/collections HTTP/1.1
Host: {{Hostname}}
Accept: application/json

GET /api/v1/collections HTTP/1.1
Host: {{Hostname}}
Accept: application/json
```

