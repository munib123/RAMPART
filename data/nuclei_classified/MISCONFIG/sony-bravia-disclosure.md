# Vulnerability: Sony BRAVIA Digital Signage 1.7.8 System API Information Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sony-bravia-disclosure.yaml`)

## Description
The application is vulnerable to sensitive information disclosure vulnerability. An unauthenticated attacker can visit several API endpoints and disclose information running on the device.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/system
```

