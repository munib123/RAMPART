# Vulnerability: Detect Gunicorn Server
**Classification:** TECH
**Source:** Nuclei Template (`gunicorn-detect.yaml`)

## Description
Gunicorn Python WSGI HTTP Server for UNIX

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

