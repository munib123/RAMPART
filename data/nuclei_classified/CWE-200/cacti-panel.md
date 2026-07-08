# Vulnerability: Cacti Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cacti-panel.yaml`)

## Description
Cacti login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/cacti/
```

