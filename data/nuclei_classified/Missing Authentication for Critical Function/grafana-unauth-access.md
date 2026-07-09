# Nuclei Template: Grafana Unauthenticated Access
**Template ID:** grafana-unauth-access
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`grafana-unauth-access.yaml`)

## Vulnerability Information & PoC

## Description
Detects Grafana instances configured with anonymous access enabled, allowing unauthenticated users to access dashboards, data sources, organization info, and potentially sensitive monitoring data without any credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/search?type=dash-db
GET {{BaseURL}}/api/dashboards/home
GET {{BaseURL}}/dashboard
GET {{BaseURL}}/api/org
GET {{BaseURL}}/api/users
GET {{BaseURL}}/api/datasources
GET {{BaseURL}}/api/frontend/settings
```

