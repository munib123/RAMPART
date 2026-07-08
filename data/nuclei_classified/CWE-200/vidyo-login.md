# Vulnerability: Vidyo Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vidyo-login.yaml`)

## Description
Vidyo admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login.html?lang=en
GET {{BaseURL}}/vr2conf/login.html
```

