# Vulnerability: Zoho ManageEngine Network Configuration Manager Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`manageengine-network-config.yaml`)

## Description
ZOHO ManageEngine Network Configuration Manager was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apiclient/ember/Login.jsp
```

