# Vulnerability: Esafenet CDG - Default Login
**Classification:** ESAFENET
**Source:** Nuclei Template (`esafenet-cdg-default-login.yaml`)

## Description
Esafenet electronic document security management system default  credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/CDGServer3/SystemConfig
```

