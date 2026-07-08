# Vulnerability: Axel WebServer - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`axel-webserver.yaml`)

## Description
Axel WebServer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

