# Vulnerability: BioTime Web Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`biotime-panel.yaml`)

## Description
BioTime Web login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login/
```

