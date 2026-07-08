# Vulnerability: Interswitch Webpay - Credentials Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`interswitch-webpay.yaml`)

## Description
Exposure of Interswitch Webpay product IDs, MAC keys and access tokens.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

