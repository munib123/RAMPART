# Vulnerability: DNT Policy Declaration
**Classification:** PRIVACY
**Source:** Nuclei Template (`dnt-policy-detect.yaml`)

## Description
Detects a Do not Track policy.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.well-known/dnt-policy.txt
```

