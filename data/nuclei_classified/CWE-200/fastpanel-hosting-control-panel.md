# Vulnerability: FASTPANEL Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fastpanel-hosting-control-panel.yaml`)

## Description
FASTPANEL login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/authentication
```

