# Vulnerability: Jaeger UI
**Classification:** MISCONFIG
**Source:** Nuclei Template (`jaeger-ui-dashboard.yaml`)

## Description
Jaeger UI dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/search
GET {{BaseURL}}/api/services
```

