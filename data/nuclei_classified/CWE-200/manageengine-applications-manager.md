# Vulnerability: ZOHO ManageEngine Applications Manager Panel - Detected
**Classification:** CWE-200
**Source:** Nuclei Template (`manageengine-applications-manager.yaml`)

## Description
ZOHO ManageEngine panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.do
```

