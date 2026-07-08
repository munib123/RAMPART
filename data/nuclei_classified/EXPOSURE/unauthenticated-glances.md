# Vulnerability: Glances Unauthenticated Panel
**Classification:** EXPOSURE
**Source:** Nuclei Template (`unauthenticated-glances.yaml`)

## Description
Glance running web server mode & Unauthenticated leads system monitoring to info disclosure

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

