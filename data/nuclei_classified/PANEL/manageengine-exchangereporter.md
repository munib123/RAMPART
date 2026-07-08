# Vulnerability: ZOHO ManageEngine Exchange Reporter Plus Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`manageengine-exchangereporter.yaml`)

## Description
ZOHO ManageEngine Exchange Reporter Plus panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/exchange/index.html
```

