# Vulnerability: XSpeeder Login - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`xspeeder-login.yaml`)

## Description
Detects the presence of XSpeeder router login panels.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/?nLang=1
```

