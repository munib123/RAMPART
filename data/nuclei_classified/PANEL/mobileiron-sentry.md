# Vulnerability: MobileIron Sentry Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`mobileiron-sentry.yaml`)

## Description
MobileIron Sentry panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mics/login.jsp
```

