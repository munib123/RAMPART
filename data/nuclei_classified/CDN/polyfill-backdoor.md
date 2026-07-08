# Vulnerability: Polyfill.io - Backdoor
**Classification:** CDN
**Source:** Nuclei Template (`polyfill-backdoor.yaml`)

## Description
The polyfill.io CDN was suspected to serve malware. Note: it's not exploitable anymore

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

