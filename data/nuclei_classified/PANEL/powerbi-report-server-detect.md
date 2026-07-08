# Vulnerability: PowerBI Report Server - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`powerbi-report-server-detect.yaml`)

## Description
PowerBI Report Server was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/reports/api/v2.0/System
GET {{BaseURL}}/reports/browse
```

