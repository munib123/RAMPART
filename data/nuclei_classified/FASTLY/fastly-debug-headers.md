# Vulnerability: Fastly CDN Debug Headers Exposure
**Classification:** FASTLY
**Source:** Nuclei Template (`fastly-debug-headers.yaml`)

## Description
Detected Fastly CDN debug headers being exposed when the Fastly-Debug header was sent in a request.This exposure disclosed sensitive debugging information such as cache paths, TTL values, content digests, surrogate keys, and cache server identities, which could help attackers understand CDN configuration and cache behavior.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

