# Vulnerability: Radarr Dashboard - Unauthenticated
**Classification:** RADARR
**Source:** Nuclei Template (`radarr-dashboard-unauth.yaml`)

## Description
Exposure of Radarr dashboard which can lead to sensitive information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

