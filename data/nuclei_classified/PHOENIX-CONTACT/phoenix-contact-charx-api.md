# Vulnerability: Phoenix Contact CHARX SEC-3XXX AC Charging Controller REST API - Detect
**Classification:** PHOENIX-CONTACT
**Source:** Nuclei Template (`phoenix-contact-charx-api.yaml`)

## Description
Phoenix Contact CHARX SEC-3XXX AC Charging Controller REST API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1.0/web/retained-data
```

