# Vulnerability: Healthchecks UI Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`healthchecks-ui-exposure.yaml`)

## Description
Healthchecks UI is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

