# Vulnerability: Forgejo End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`forgejo-eol.yaml`)

## Description
Detected Forgejo versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/v1/version
```

