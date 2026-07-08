# Vulnerability: Avigilon Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`avigilon-panel.yaml`)

## Description
Avigilon login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cfg/login
```

