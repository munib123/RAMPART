# Vulnerability: SSL/SSH/TLS/JWT Keys - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`server-private-keys.yaml`)

## Description
Private SSL, SSH, TLS, and JWT keys were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

