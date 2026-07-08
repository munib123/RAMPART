# Vulnerability: TOPdesk - Detect
**Classification:** TOPDESK
**Source:** Nuclei Template (`topdesk-detect.yaml`)

## Description
Detects the use of TOPdesk, a web-based IT service management (ITSM) and helpdesk platform. Identification is based on unique page titles, HTML patterns.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

