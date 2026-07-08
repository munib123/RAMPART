# Vulnerability: OpenProject - Detect
**Classification:** TECH
**Source:** Nuclei Template (`openproject-detect.yaml`)

## Description
OpenProject is an open source web-based project management software.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/v3
GET {{BaseURL}}/activity.atom
```

