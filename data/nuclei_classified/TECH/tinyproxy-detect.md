# Vulnerability: Tinyproxy - Detect
**Classification:** TECH
**Source:** Nuclei Template (`tinyproxy-detect.yaml`)

## Description
Lightweight HTTP/HTTPS proxy daemon for POSIX operating systems

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

