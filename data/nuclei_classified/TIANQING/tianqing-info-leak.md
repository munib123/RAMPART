# Vulnerability: Tianqing Info Leak
**Classification:** TIANQING
**Source:** Nuclei Template (`tianqing-info-leak.yaml`)

## Description
Information exposed in Tianqing.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/dbstat/gettablessize
```

