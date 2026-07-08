# Vulnerability: Apigee Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`apigee-panel.yaml`)

## Description
Apigee login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

