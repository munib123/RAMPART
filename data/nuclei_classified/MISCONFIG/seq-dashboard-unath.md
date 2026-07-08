# Vulnerability: Seq Dashboard - Unauthenticated
**Classification:** MISCONFIG
**Source:** Nuclei Template (`seq-dashboard-unath.yaml`)

## Description
Seq is exposed without authentication

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/dashboards
```

