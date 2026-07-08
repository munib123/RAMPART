# Vulnerability: OpenResty detection
**Classification:** TECH
**Source:** Nuclei Template (`openresty-detect.yaml`)

## Description
Some deployments of OpenResty spill their version numbers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

