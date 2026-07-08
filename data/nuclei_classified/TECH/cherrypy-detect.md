# Vulnerability: CherryPy Web Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`cherrypy-detect.yaml`)

## Description
Detects servers running the CherryPy web server by identifying the Server header in HTTP responses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

