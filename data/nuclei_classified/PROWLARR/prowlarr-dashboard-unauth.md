# Vulnerability: Prowlarr Dashboard - Unauthenticated
**Classification:** PROWLARR
**Source:** Nuclei Template (`prowlarr-dashboard-unauth.yaml`)

## Description
Exposure of Prowlarr dashboard which can lead to sensitive information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

