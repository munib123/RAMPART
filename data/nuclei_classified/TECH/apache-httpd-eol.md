# Vulnerability: Apache HTTP Server End-of-Life - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-httpd-eol.yaml`)

## Description
Detected Apache HTTP Server versions that have reached End-of-Life (EOL) and no longer receive security updates.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

