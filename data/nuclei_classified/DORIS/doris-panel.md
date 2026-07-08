# Vulnerability: Doris Panel - Detect
**Classification:** DORIS
**Source:** Nuclei Template (`doris-panel.yaml`)

## Description
Doris panel detection template.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

