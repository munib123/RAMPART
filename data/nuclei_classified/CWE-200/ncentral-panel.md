# Vulnerability: N-central Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ncentral-panel.yaml`)

## Description
N-central login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

