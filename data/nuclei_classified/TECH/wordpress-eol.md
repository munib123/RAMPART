# Vulnerability: WordPress End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`wordpress-eol.yaml`)

## Description
Detected WordPress versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

