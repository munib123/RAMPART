# Vulnerability: Anteon Dashboard - Unauthenticated
**Classification:** ANTEON
**Source:** Nuclei Template (`anteon-dashboard-unauth.yaml`)

## Description
The Anteon Dashboard was found to be accessible via the /dashboard endpoint without authentication.This exposure may allow unauthorized users to gain insights into internal services, configurations, or sensitive operational data depending on the permissions and features enabled on the dashboard.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard
```

