# Vulnerability: Dynatrace RUM - Tech Detect
**Classification:** TECH
**Source:** Nuclei Template (`dynatrace-rum-detect.yaml`)

## Description
Detects Dynatrace Real User Monitoring (RUM) and OneAgent artifacts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

