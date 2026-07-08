# Vulnerability: Gopher Server - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`gopher-server.yaml`)

## Description
Gopher Server is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

