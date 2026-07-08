# Vulnerability: ZOHO ManageEngine Analytics Plus Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`manageengine-analytics.yaml`)

## Description
ZOHO ManageEngine analytics plus panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/iam/login
```

