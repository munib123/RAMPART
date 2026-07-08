# Vulnerability: FlowWeb Web Server - Detection
**Classification:** TECH
**Source:** Nuclei Template (`flowweb-detect.yaml`)

## Description
Detected servers running the FlowWeb web server via the Server header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

