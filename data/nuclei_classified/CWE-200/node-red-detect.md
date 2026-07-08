# Vulnerability: Node-RED Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`node-red-detect.yaml`)

## Description
Node-RED dashboard was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

