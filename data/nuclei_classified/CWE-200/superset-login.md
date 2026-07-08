# Vulnerability: Apache Superset Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`superset-login.yaml`)

## Description
Apache Superset login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

