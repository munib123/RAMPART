# Vulnerability: ProcessWire Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`processwire-login.yaml`)

## Description
ProcessWire login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/processwire/
```

