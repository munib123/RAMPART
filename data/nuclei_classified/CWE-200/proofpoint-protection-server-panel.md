# Vulnerability: Proofpoint Protection Server Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`proofpoint-protection-server-panel.yaml`)

## Description
Proofpoint Protection Server panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/euweb/login
```

