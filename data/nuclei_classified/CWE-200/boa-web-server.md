# Vulnerability: Boa Web Server - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`boa-web-server.yaml`)

## Description
Boa is a single-tasking HTTP server. That means that unlike traditional web servers, it does not fork for each incoming connection, nor does it fork many copies of itself to handle multiple connections.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

