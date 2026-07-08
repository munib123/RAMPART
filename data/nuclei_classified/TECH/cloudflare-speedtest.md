# Vulnerability: Cloudflare Speedtest - Detect
**Classification:** TECH
**Source:** Nuclei Template (`cloudflare-speedtest.yaml`)

## Description
Detected the exposed default page of the Cloudflare Speedtest service.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

