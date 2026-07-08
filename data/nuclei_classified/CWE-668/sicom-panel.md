# Vulnerability: Sicom MGRNG - Administrative Login Found
**Classification:** CWE-668
**Source:** Nuclei Template (`sicom-panel.yaml`)

## Description
Sicom MGRNG administrative login page found.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/~sicom/mgrng/LoginForm.php
```

