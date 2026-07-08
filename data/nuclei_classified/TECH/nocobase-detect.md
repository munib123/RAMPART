# Vulnerability: NocoBase - Detect
**Classification:** TECH
**Source:** Nuclei Template (`nocobase-detect.yaml`)

## Description
NocoBase is an open source, extensibility-first, low-code platform for building business applications and enterprise solutions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

