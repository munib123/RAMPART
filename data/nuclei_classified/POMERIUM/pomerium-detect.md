# Vulnerability: Pomerium Detect
**Classification:** POMERIUM
**Source:** Nuclei Template (`pomerium-detect.yaml`)

## Description
A Pomerium SSO Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.pomerium/index.js
```

