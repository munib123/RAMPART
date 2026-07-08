# Vulnerability: MailWatch Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mailwatch-login.yaml`)

## Description
MailWatch login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mailscanner/login.php
```

