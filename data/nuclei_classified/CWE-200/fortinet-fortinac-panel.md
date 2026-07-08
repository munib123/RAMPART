# Vulnerability: Fortinet FortiNAC Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortinet-fortinac-panel.yaml`)

## Description
Fortinet FortiNAC login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/WelcomeActions.jsp?action=ajaxGetWelcomeViewInfo
```

