# Vulnerability: YOURLS - Detection
**Classification:** TECH
**Source:** Nuclei Template (`yourls-detect.yaml`)

## Description
Detects if the target is running a YOURLS (Your Own URL Shortener) server

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

