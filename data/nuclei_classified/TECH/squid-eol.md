# Vulnerability: Squid End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`squid-eol.yaml`)

## Description
Detected Squid proxy versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

