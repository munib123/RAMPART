# Vulnerability: SOGo Detect
**Classification:** SOGO
**Source:** Nuclei Template (`sogo-detect.yaml`)

## Description
This template will detect a running SOGo instance

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/SOGo
```

