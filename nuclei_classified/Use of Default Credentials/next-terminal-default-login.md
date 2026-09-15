# Nuclei Template: Next Terminal - Default Login
**Template ID:** next-terminal-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`next-terminal-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Next Terminal default login was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","remember":false}
```

## References
- https://github.com/dushixiang/next-terminal
