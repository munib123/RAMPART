# Vulnerability: Linkerd SSRF detection
**Classification:** SSRF
**Source:** Nuclei Template (`linkerd-ssrf-detect.yaml`)

## Description
Linkerd is vulnerable to SSRF.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

