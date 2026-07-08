# Vulnerability: SAP Logon Error Message
**Classification:** SAP
**Source:** Nuclei Template (`sap-logon-error-message.yaml`)

## Description
Identifies "Logon Error Message" in the SAP Internet Communication Framework which returns a 404 status code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

