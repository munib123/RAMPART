# Vulnerability: SecNet Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`secnet-ac-panel.yaml`)

## Description
SecNet login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

