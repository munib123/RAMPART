# Vulnerability: Nginx End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`nginx-eol.yaml`)

## Description
Detected Nginx versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

