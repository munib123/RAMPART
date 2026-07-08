# Vulnerability: Watershed Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`watershed-panel.yaml`)

## Description
Watershed login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app/outside.html#/signin
```

