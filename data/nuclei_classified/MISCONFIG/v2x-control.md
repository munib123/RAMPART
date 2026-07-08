# Vulnerability: V2X Control - Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`v2x-control.yaml`)

## Description
V2X Control Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

