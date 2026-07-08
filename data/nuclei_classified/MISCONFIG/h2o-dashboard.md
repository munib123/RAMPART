# Vulnerability: H2O Dashboard - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`h2o-dashboard.yaml`)

## Description
H2o dashboard by default has no authentication and can lead to RCE on the host.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

