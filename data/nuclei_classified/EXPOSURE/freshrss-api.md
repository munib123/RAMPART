# Vulnerability: FreshRSS Google Reader API Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`freshrss-api.yaml`)

## Description
Detected an exposed FreshRSS instance with the Google Reader API enabled, which could have allowed unauthorized access to RSS feeds and user-related data via accessible API endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/
```

