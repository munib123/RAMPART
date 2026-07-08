# Vulnerability: Sysreptor - Detection
**Classification:** TECH
**Source:** Nuclei Template (`sysreptor-detect.yaml`)

## Description
Detects a Sysreptor server, a customizable and powerful penetration testing reporting platform for offensive security professionals.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{nuxjs}} HTTP/1.1
Host: {{BaseURL}}
Content-type: text/javascript; charset="utf-8"
```

