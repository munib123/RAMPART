# Vulnerability: Fastly Backend Server Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`fastly-backend-info-disclosure.yaml`)

## Description
Detected Fastly CDN misconfigured and exposing backend/origin server IP addresses or hostnames in HTTP response headers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

