# Vulnerability: ServiceNow Stats Page - Detection
**Classification:** SERVICENOW
**Source:** Nuclei Template (`servicenow-stats-page.yaml`)

## Description
Detects exposed ServiceNow statistics pages (stats.do) that reveal system information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/stats.do
```

