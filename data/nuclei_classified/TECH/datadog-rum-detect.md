# Vulnerability: Datadog Browser RUM - Detect
**Classification:** TECH
**Source:** Nuclei Template (`datadog-rum-detect.yaml`)

## Description
Detects Datadog Browser RUM (Real User Monitoring) SDK artifacts in HTML responses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

