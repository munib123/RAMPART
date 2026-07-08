# Vulnerability: Pa11y Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`pa11y-dashboard.yaml`)

## Description
Pa11y Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

