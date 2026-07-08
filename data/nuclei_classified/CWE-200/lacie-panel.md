# Vulnerability: LaCie Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lacie-panel.yaml`)

## Description
LaCie login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/dashboard/
```

