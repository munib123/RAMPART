# Vulnerability: Netsparker Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netsparker-panel.yaml`)

## Description
Netsparker login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/account/signin?ReturnUrl=%2f
```

