# Vulnerability: ZOHO ManageEngine APEX IT Help-Desk Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`manageengine-apex-helpdesk.yaml`)

## Description
ZOHO MangageEngine APEX panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jsp/index.jsp
```

