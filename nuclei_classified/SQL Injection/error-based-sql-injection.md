# Nuclei Template: Error based SQL injection
**Template ID:** error-based-sql-injection
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`error-based-sql-injection.yaml`)

## Vulnerability Information & PoC

## Description
A SQL injection vulnerability was identified based on an error message returned by the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/'
```

