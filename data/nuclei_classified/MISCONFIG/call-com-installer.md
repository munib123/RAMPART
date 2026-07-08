# Vulnerability: Call.com Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`call-com-installer.yaml`)

## Description
Detects exposed Call.com  Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/setup
```

