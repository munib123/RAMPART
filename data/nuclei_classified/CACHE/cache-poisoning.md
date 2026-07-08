# Vulnerability: Cache Poisoning Detection
**Classification:** CACHE
**Source:** Nuclei Template (`cache-poisoning.yaml`)

## Description
This template detects Cache poisoning.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?{{cache_key}}=9 HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Prefix: {{cache_header}}.xfp
X-Forwarded-Host: {{cache_header}}.xfh
X-Forwarded-For: {{cache_header}}.xff

GET /?{{cache_key}}=9 HTTP/1.1
Host: {{Hostname}}
```

