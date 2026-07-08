# Vulnerability: Trust Center Page - Detect
**Classification:** MISC
**Source:** Nuclei Template (`trust-center-detect.yaml`)

## Description
Detected the presence of Trust Center pages or subdomains provided by Safebase, Vanta, or TrustCloud.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/trust
GET {{BaseURL}}/trust-center
GET {{BaseURL}}/trust-center.html
GET {{BaseURL}}/security
GET {{BaseURL}}/compliance
```

