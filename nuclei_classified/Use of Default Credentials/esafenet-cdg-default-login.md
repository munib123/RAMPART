# Nuclei Template: Esafenet CDG - Default Login
**Template ID:** esafenet-cdg-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`esafenet-cdg-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Esafenet electronic document security management system default  credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/CDGServer3/SystemConfig
```

