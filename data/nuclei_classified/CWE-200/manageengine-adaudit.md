# Vulnerability: ZOHO ManageEngine ADAudit/ADManager Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`manageengine-adaudit.yaml`)

## Description
ZOHO ManageEngine ADAudit/ADManager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/authorization.do
```

