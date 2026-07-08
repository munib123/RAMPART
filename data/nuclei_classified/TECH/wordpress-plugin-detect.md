# Vulnerability: Wordpress Plugin Detection
**Classification:** TECH
**Source:** Nuclei Template (`wordpress-plugin-detect.yaml`)

## Description
Detects installed WordPress plugins by analyzing HTTP responses and common plugin paths

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

