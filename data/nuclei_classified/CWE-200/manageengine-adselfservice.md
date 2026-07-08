# Vulnerability: ZOHO ManageEngine ADSelfService Plus - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`manageengine-adselfservice.yaml`)

## Description
ZOHO ManageEngine ADSelfService panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/authorization.do
GET {{BaseURL}}/servlet/GetProductVersion
```

