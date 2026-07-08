# Vulnerability: Codian MCU Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`codian-mcu-login.yaml`)

## Description
Codian MCU login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

