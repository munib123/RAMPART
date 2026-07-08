# Vulnerability: Cisco Edge 340 Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-edge-340.yaml`)

## Description
Cisco Edge 340 panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/?next=%2F
```

