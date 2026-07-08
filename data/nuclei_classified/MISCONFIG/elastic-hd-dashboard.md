# Vulnerability: Elastic HD Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`elastic-hd-dashboard.yaml`)

## Description
Elastic HD Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

