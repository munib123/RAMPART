# Vulnerability: Faraday Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`faraday-login.yaml`)

## Description
Faraday login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login
```

