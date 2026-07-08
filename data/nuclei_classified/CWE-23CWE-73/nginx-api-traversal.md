# Vulnerability: Nginx Plus Rest API - Traversal
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`nginx-api-traversal.yaml`)

## Description
Access to Nginx Plus Rest API was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

