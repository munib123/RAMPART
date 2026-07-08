# Vulnerability: Web Proxy Auto-Discovery Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`proxy-wpad-exposure.yaml`)

## Description
Web Proxy Auto-Discovery configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wpad.dat
```

