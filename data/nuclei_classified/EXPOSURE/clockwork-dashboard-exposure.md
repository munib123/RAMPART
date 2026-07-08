# Vulnerability: Clockwork Dashboard Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`clockwork-dashboard-exposure.yaml`)

## Description
Clockwork Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/__clockwork/latest
```

