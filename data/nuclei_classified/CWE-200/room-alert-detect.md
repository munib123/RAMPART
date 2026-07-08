# Vulnerability: AVTECH Room Alert Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`room-alert-detect.yaml`)

## Description
AVTECH Room Alert login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.html
GET {{BaseURL}}/gateway
```

