# Vulnerability: CrushFTP - Anonymous Login
**Classification:** DEFAULT-LOGINS
**Source:** Nuclei Template (`crushftp-anonymous-login.yaml`)

## Description
CrushFTP Anonymous login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /WebInterface/ HTTP/1.1
Host: {{Hostname}}

POST /WebInterface/function/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

command=getUsername&random=0.4186510822713485&c2f={{auth}}
```

