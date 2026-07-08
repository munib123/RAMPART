# Vulnerability: NetAlert X Admin Dashboard - Exposed
**Classification:** NETALERTX
**Source:** Nuclei Template (`netalertx-dashboard.yaml`)

## Description
Unauthorized access to the NetAlert X Admin Dashboard.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/devices.php
```

