# Nuclei Template: Linkerd SSRF detection
**Template ID:** linkerd-ssrf-detection
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**Source:** Nuclei Template (`linkerd-ssrf-detect.yaml`)

## Vulnerability Information & PoC

## Description
Linkerd is vulnerable to SSRF.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://twitter.com/nirvana_msu/status/1084144955034165248
