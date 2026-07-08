# Vulnerability: IBM WebSphere Application Server
**Classification:** TECH
**Source:** Nuclei Template (`websphere-detect.yaml`)

## Description
Detects servers running IBM WebSphere Application Server via the Server header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

