# Vulnerability: Cisco WebVPN Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-webvpn-detect.yaml`)

## Description
Cisco WebVPN panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/webvpn.html
```

