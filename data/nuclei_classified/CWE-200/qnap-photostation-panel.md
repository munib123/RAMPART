# Vulnerability: QNAP Photo Station Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`qnap-photostation-panel.yaml`)

## Description
QNAP Photo Station panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/photo/
```

