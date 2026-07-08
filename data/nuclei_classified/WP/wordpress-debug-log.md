# Vulnerability: WordPress Debug Log - Exposure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-debug-log.yaml`)

## Description
Exposed Wordpress debug log.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{paths}}/debug.log
```

