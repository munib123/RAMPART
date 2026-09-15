# Nuclei Template: Fastly Backend Server Information Disclosure
**Template ID:** fastly-backend-info-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`fastly-backend-info-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Fastly CDN misconfigured and exposing backend/origin server IP addresses or hostnames in HTTP response headers.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://developer.fastly.com/reference/http/http-headers/
