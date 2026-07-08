# Vulnerability: Docmosis Tornado Server Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`docmosis-tornado-server.yaml`)

## Description
Docmosis Tornado Server is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

