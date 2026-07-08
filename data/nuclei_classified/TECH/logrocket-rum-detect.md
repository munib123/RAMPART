# Vulnerability: LogRocket RUM - Detect
**Classification:** TECH
**Source:** Nuclei Template (`logrocket-rum-detect.yaml`)

## Description
Detects LogRocket Session Replay & Frontend Monitoring artifacts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

