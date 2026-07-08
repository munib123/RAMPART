# Vulnerability: Jalios JCMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jcms-panel.yaml`)

## Description
Jalios JCMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/front/privateLogin.jsp
```

