# Vulnerability: AKHQ Panel - Detect
**Classification:** AKHQ
**Source:** Nuclei Template (`akhq-panel.yaml`)

## Description
AKHQ Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/login
```

