# Vulnerability: Lighttpd Web Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`lighttpd-detect.yaml`)

## Description
Detected servers running the Lighttpd web server by identifying the Server header in HTTP responses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

