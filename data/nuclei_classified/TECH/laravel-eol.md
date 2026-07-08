# Vulnerability: Laravel End-of-Life Detection
**Classification:** TECH
**Source:** Nuclei Template (`laravel-eol.yaml`)

## Description
Detected Laravel framework versions that had reached End-of-Life (EOL) and no longer received security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/composer.json
GET {{BaseURL}}/composer.lock
```

