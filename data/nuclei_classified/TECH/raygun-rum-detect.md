# Vulnerability: Raygun RUM - Detect
**Classification:** TECH
**Source:** Nuclei Template (`raygun-rum-detect.yaml`)

## Description
Detects ACTIVE Raygun (Raygun4JS) Error Tracking & Real User Monitoring implementations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

