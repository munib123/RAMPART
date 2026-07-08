# Vulnerability: Prometheus Monitoring System - Unauthenticated
**Classification:** UNAUTH
**Source:** Nuclei Template (`prometheus-unauth.yaml`)

## Description
Detects unauthenticated access to Prometheus Time Series Collection and Processing Server by checking for specific elements in the response from the `/graph` endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config
GET {{BaseURL}}/api/v1/status/config
```

