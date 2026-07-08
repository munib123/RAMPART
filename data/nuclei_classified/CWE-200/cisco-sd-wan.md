# Vulnerability: Cisco SD-WAN Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-sd-wan.yaml`)

## Description
Cisco SD-WAN login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

