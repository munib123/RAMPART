# Vulnerability: SquirrelMail Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`squirrelmail-login.yaml`)

## Description
SquirrelMail login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/src/login.php
GET {{BaseURL}}/webmail/src/login.php
GET {{BaseURL}}/squirrelmail/src/login.php
```

