# Vulnerability: Discover production log files
**Classification:** EXPOSURE
**Source:** Nuclei Template (`production-logs.yaml`)

## Description
Production log file was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/log/production.log
GET {{BaseURL}}/logs/production.log
GET {{BaseURL}}/production.log
```

