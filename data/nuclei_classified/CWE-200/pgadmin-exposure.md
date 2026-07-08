# Vulnerability: PostgreSQL pgAdmin Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pgadmin-exposure.yaml`)

## Description
PostgreSQL pgAdmin Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/browser/
```

