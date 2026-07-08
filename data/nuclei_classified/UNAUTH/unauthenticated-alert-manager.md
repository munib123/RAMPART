# Vulnerability: Alert Manager - Unauthenticated Access
**Classification:** UNAUTH
**Source:** Nuclei Template (`unauthenticated-alert-manager.yaml`)

## Description
Alert Manager was able to be accessed with no authentication requirements in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/alerts
```

