# Vulnerability: Lidarr Dashboard - Unauthenticated
**Classification:** LIDARR
**Source:** Nuclei Template (`lidarr-dashboard-unauth.yaml`)

## Description
Exposed Lidarr was detected which can lead to sensitive information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

