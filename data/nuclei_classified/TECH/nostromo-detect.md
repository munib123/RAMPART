# Vulnerability: Nostromo Web Server
**Classification:** TECH
**Source:** Nuclei Template (`nostromo-detect.yaml`)

## Description
Detected servers running the Nostromo web server by identifying the Server header in HTTP responses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

