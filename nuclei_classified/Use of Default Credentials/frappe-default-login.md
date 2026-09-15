# Nuclei Template: Frappe Framework - Default Login Credentials
**Template ID:** frappe-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`frappe-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Frappe Framework (and ERPNext) is accessible using the default credentials Administrator:admin. Successful login exposes full administrative access to the ERP/CRM system and underlying data.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/api/method/login
```

## References
- https://frappeframework.com
- https://docs.erpnext.com
