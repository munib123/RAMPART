# Vulnerability: ZOHO ManageEngine Desktop Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`manageengine-desktop.yaml`)

## Description
ZOHO ManageEngine desktop panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/configurations
```

