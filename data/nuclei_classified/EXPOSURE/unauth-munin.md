# Vulnerability: Munin Monitoring Dashboard - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`unauth-munin.yaml`)

## Description
Detected Munin monitoring dashboard, exposing system metrics and server statistics.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/munin/
```

