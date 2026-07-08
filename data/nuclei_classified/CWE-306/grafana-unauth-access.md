# Vulnerability: Grafana Unauthenticated Access
**Classification:** CWE-306
**Source:** Nuclei Template (`grafana-unauth-access.yaml`)

## Description
Detects Grafana instances configured with anonymous access enabled, allowing unauthenticated users to access dashboards, data sources, organization info, and potentially sensitive monitoring data without any credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/search?type=dash-db
GET {{BaseURL}}/api/dashboards/home
GET {{BaseURL}}/dashboard
GET {{BaseURL}}/api/org
GET {{BaseURL}}/api/users
GET {{BaseURL}}/api/datasources
GET {{BaseURL}}/api/frontend/settings
```

