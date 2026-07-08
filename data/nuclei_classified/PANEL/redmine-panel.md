# Vulnerability: Redmine Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`redmine-panel.yaml`)

## Description
Redmine login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

