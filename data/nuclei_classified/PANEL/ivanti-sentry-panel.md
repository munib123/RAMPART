# Vulnerability: Ivanti Sentry Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ivanti-sentry-panel.yaml`)

## Description
Ivanti Sentry panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mics/login.jsp
```

