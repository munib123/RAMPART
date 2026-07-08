# Vulnerability: Discover development log files
**Classification:** LOGS
**Source:** Nuclei Template (`development-logs.yaml`)

## Description
Development log file was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/log/development.log
GET {{BaseURL}}/logs/development.log
GET {{BaseURL}}/development.log
```

