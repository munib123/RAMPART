# Vulnerability: Discover wp-app.log Files
**Classification:** EXPOSURE
**Source:** Nuclei Template (`wp-app-log.yaml`)

## Description
wp-app.log file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-app.log
```

