# Vulnerability: Simple CRM 3.0 SQL Injection and Authentication Bypass
**Classification:** CWE-89
**Source:** Nuclei Template (`simple-crm-sql-injection.yaml`)

## Description
Simple CRM 3.0 is susceptible to SQL injection and authentication bypass vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/scrm/crm/admin
```

