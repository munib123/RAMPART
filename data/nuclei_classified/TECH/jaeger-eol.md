# Vulnerability: Jaeger End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`jaeger-eol.yaml`)

## Description
Detected Jaeger versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

