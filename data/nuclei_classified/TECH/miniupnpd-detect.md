# Vulnerability: MiniUPnPd - Detect
**Classification:** TECH
**Source:** Nuclei Template (`miniupnpd-detect.yaml`)

## Description
Detected servers using the MiniUPnPd service through the Server header.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

