# Nuclei Template: Simple CRM 3.0 SQL Injection and Authentication Bypass
**Template ID:** simple-crm-sql-injection
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`simple-crm-sql-injection.yaml`)

## Vulnerability Information & PoC

## Description
Simple CRM 3.0 is susceptible to SQL injection and authentication bypass vulnerabilities.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/scrm/crm/admin
```

## References
- https://packetstormsecurity.com/files/163254/simplecrm30-sql.txt
