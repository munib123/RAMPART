# Vulnerability: Detect websites using Herokuapp endpoints
**Classification:** HEROKU
**Source:** Nuclei Template (`herokuapp-detect.yaml`)

## Description
Detected endpoints might be vulnerable to subdomain takeover or disclose sensitive info

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

