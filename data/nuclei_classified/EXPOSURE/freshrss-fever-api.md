# Vulnerability: FreshRSS Fever API - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`freshrss-fever-api.yaml`)

## Description
Detected an exposed FreshRSS instance with the Fever API enabled, which could allow unauthorized access to RSS feed data and user-related information via accessible Fever-compatible API endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/
```

