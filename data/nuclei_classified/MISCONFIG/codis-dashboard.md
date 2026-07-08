# Vulnerability: Codis Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`codis-dashboard.yaml`)

## Description
Codis Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

