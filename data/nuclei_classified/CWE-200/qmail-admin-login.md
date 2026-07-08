# Vulnerability: QmailAdmin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`qmail-admin-login.yaml`)

## Description
QmailAdmin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/qmailadmin/qmailadmin.cgi
GET {{BaseURL}}/cgi-bin/qmailadmin/qmailadmin
GET {{BaseURL}}/cgi-bin/qmailadmin
GET {{BaseURL}}/cgi-ssl/qmailadmin/qmailadmin
```

