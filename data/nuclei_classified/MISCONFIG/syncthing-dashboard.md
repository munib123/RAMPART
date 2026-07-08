# Vulnerability: Syncthing Dashboard Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`syncthing-dashboard.yaml`)

## Description
Syncthing Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

