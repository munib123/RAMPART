# Nuclei Template: Apache htpasswd Config - Detect
**Template ID:** htpasswd-detection
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`htpasswd-detection.yaml`)

## Vulnerability Information & PoC

## Description
Apache htpasswd configuration was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.htpasswd
```

## References
- https://httpd.apache.org/docs/current/programs/htpasswd.html
