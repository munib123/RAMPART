# Vulnerability: Magnolia CMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`magnolia-panel.yaml`)

## Description
Magnolia CMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/.magnolia/admincentral
```

