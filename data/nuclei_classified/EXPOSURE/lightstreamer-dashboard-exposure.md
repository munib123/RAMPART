# Vulnerability: Lightstreamer Dashboard Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`lightstreamer-dashboard-exposure.yaml`)

## Description
Detected exposed Lightstreamer Server dashboard that may reveal server configuration,real-time monitoring data, session information, and internal infrastructure details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard/
GET {{BaseURL}}/lightstreamer/dashboard/
```

