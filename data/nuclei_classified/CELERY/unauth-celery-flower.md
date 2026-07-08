# Vulnerability: Celery Flower - Unauthenticated Access
**Classification:** CELERY
**Source:** Nuclei Template (`unauth-celery-flower.yaml`)

## Description
Celery Flower was able to be accessed with no authentication requirements in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard
```

