# Vulnerability: Error based SQL injection
**Classification:** CWE-89
**Source:** Nuclei Template (`error-based-sql-injection.yaml`)

## Description
A SQL injection vulnerability was identified based on an error message returned by the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/'
```

