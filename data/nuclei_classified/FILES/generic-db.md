# Vulnerability: Generic Database File - Exposure
**Classification:** FILES
**Source:** Nuclei Template (`generic-db.yaml`)

## Description
This is collection of some web frameworks recommendation or default configuration for SQLite database file location. If this file is publicly accessible due to server misconfiguration, it could result in application data leak including users sensitive data, password hashes etc.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{path}}
```

