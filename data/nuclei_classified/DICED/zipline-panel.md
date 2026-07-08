# Vulnerability: Diced Zipline - Detect
**Classification:** DICED
**Source:** Nuclei Template (`zipline-panel.yaml`)

## Description
Zipline panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

