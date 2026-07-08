# Vulnerability: New Relic Browser Monitoring (RUM) - Tech Detect
**Classification:** TECH
**Source:** Nuclei Template (`newrelic-rum-detect.yaml`)

## Description
Detected New Relic Browser Monitoring (RUM) agent artifacts

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

