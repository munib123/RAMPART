# Vulnerability: Bugzilla - Detect
**Classification:** TECH
**Source:** Nuclei Template (`bugzilla-detect.yaml`)

## Description
Detects a Bugzilla server, official repository for the Bugzilla bug tracking system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

