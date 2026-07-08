# Vulnerability: Openfire Admin Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openfire-admin-panel.yaml`)

## Description
Openfire Admin Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login.jsp
```

