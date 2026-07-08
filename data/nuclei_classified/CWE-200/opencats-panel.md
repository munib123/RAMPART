# Vulnerability: OpenCATS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opencats-panel.yaml`)

## Description
OpenCATS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/opencats/
```

