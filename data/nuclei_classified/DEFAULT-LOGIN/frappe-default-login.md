# Vulnerability: Frappe Framework - Default Login Credentials
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`frappe-default-login.yaml`)

## Description
Frappe Framework (and ERPNext) is accessible using the default credentials Administrator:admin. Successful login exposes full administrative access to the ERP/CRM system and underlying data.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/api/method/login
```

