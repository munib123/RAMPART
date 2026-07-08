# Vulnerability: Database Credentials File Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`database-credentials.yaml`)

## Description
Internal file exposed containing database credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/database_credentials.inc
```

