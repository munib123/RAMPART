# Vulnerability: Woodpecker - Detect
**Classification:** TECH
**Source:** Nuclei Template (`woodpecker-detect.yaml`)

## Description
Woodpecker was detected — a lightweight, powerful CI/CD engine with great extensibility.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web-config.js
```

