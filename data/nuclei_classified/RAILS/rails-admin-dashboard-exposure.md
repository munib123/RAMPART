# Vulnerability: RailsAdmin Dashboard Exposure
**Classification:** RAILS
**Source:** Nuclei Template (`rails-admin-dashboard-exposure.yaml`)

## Description
Detected RailsAdmin dashboard was exposed without proper authentication, allowing unauthorized access to data management interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin
GET {{BaseURL}}/rails_admin
```

