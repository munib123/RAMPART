# Vulnerability: Dell OpenManage Switch Administrator Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dell-openmanager-login.yaml`)

## Description
Dell OpenManage Switch Administrator login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/config/authentication_page.htm
```

