# Vulnerability: Paystack Secret/Live Key - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`paystack-secret-live.yaml`)

## Description
Detected exposed Paystack secret keys (test or live) found in application source code, configuration files, or client-side assets.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

