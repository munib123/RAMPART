# Vulnerability: ZOHO ManageEngine KeyManagerPlus Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`manageengine-keymanagerplus.yaml`)

## Description
ZOHO ManageEngine KeyManagerPlus panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apiclient/index.jsp
GET {{BaseURL}}/pki/images/keyManager_title.ico
```

