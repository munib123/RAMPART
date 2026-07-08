# Vulnerability: Traggo Time Tracking Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`traggo-server-detect.yaml`)

## Description
Detected Traggo time tracking server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query":"{ version { name commit buildDate } }"}
```

