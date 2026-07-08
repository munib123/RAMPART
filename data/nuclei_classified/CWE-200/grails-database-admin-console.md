# Vulnerability: Grails Admin Console Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`grails-database-admin-console.yaml`)

## Description
Grails Admin Console panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dbconsole/
GET {{BaseURL}}/h2-console/
```

