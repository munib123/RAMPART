# Vulnerability: GMail API - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gmail-api-client-secrets.yaml`)

## Description
GMail API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/client_secrets.json
```

