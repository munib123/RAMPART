# Vulnerability: Dell Laser Printer - Unauthenticated Detect
**Classification:** DELL
**Source:** Nuclei Template (`dell-laser-printer-unauth.yaml`)

## Description
The Dell Laser Printer web interface was accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/cgi-bin/dynamic/config/secure/security.html
```

