# Vulnerability: Microsoft Exchange Server Detect
**Classification:** MICROSOFT
**Source:** Nuclei Template (`ms-exchange-server.yaml`)

## Description
Check for presence of Exchange Server using Outlook Web App path data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/owa/auth/logon.aspx
```

