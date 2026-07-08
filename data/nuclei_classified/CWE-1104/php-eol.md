# Vulnerability: PHP End-of-Life - Detect
**Classification:** CWE-1104
**Source:** Nuclei Template (`php-eol.yaml`)

## Description
Detected PHP versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

