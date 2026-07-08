# Vulnerability: Micro Focus Filr Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`microfocus-filr-panel.yaml`)

## Description
Micro Focus Filr login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/filr/login
GET {{BaseURL}}/login
```

