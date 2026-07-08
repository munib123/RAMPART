# Vulnerability: Ipswitch IMail Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`ipswitch-imail-detect.yaml`)

## Description
Detects servers running Ipswitch IMail by identifying the Server header in HTTP responses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

