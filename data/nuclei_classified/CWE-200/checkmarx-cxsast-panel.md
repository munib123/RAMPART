# Vulnerability: Checkmarx CxSAST Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`checkmarx-cxsast-panel.yaml`)

## Description
Checkmarx CxSAST login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cxrestapi/help/system/version
GET {{BaseURL}}/cxwebclient/Login.aspx
GET {{BaseURL}}/cxrestapi/auth/identity/.well-known/openid-configuration
```

