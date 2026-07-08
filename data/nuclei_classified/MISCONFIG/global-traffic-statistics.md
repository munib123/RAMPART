# Vulnerability: Global Traffic Statistics Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`global-traffic-statistics.yaml`)

## Description
Global Traffic Statistics page is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

