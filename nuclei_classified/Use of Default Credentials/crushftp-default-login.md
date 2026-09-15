# Nuclei Template: CrushFTP - Default Login
**Template ID:** crushftp-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`crushftp-default-login.yaml`)

## Vulnerability Information & PoC

## Description
CrushFTP default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /WebInterface/ HTTP/1.1
Host: {{Hostname}}

POST /WebInterface/function/ HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/WebInterface/login.html

command=login&username={{username}}&password={{password}}&encoded=true&language=en&random=0.34712915617878926
```

