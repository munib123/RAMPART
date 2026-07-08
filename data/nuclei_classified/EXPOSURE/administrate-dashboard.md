# Vulnerability: Administrate Dashboard Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`administrate-dashboard.yaml`)

## Description
Administrate Dashboard was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin
```

