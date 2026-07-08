# Vulnerability: ONLYOFFICE Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`onlyoffice-login-panel.yaml`)

## Description
ONLYOFFICE Community Server is a free open-source collaborative system developed to manage documents, projects, customer relationship and email correspondence.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/auth.aspx
```

