# Vulnerability: Ametys Admin Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`ametys-admin-login.yaml`)

## Description
An Ametys admin login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_admin/index.html
```

