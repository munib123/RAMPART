# Vulnerability: Wordpress Theme Detection
**Classification:** TECH
**Source:** Nuclei Template (`wordpress-theme-detect.yaml`)

## Description
Detects installed WordPress themes by analyzing HTTP responses and theme-specific paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

