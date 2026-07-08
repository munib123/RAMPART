# Vulnerability: Structurizr Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`structurizr-panel.yaml`)

## Description
Structurizr login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/signin
```

