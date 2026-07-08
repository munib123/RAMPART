# Vulnerability: Sonarr Dashboard - Unauthenticated
**Classification:** SONARR
**Source:** Nuclei Template (`sonarr-dashboard-unauth.yaml`)

## Description
Exposure of Sonarr dashboard which can lead to sensitive information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

