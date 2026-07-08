# Vulnerability: zm-system-log-detect
**Classification:** LOGS
**Source:** Nuclei Template (`zm-system-log-detect.yaml`)

## Description
Zm system log file exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?view=log
GET {{BaseURL}}/zm/?view=log
```

