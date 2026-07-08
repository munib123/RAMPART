# Vulnerability: SqWebMail Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sqwebmail-login-panel.yaml`)

## Description
SqWebMail login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/sqwebmail
GET {{BaseURL}}/cgi-bin/webmail
```

