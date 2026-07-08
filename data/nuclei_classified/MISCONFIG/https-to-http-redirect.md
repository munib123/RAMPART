# Vulnerability: HTTPS to HTTP redirect Misconfiguration
**Classification:** MISCONFIG
**Source:** Nuclei Template (`https-to-http-redirect.yaml`)

## Description
Detects whether there is a redirect from https:// to http://

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

