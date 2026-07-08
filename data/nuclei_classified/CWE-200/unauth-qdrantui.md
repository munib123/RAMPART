# Vulnerability: Qdrant UI - Unauthenticated Access
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-qdrantui.yaml`)

## Description
Qdrant UI Dashboard was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/collections
```

