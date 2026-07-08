# Vulnerability: Ray Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ray-dashboard.yaml`)

## Description
Ray Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

