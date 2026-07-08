# Vulnerability: ServiceNow Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`servicenow-panel.yaml`)

## Description
ServiceNow Login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.do
```

