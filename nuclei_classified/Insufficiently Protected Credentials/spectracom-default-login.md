# Nuclei Template: Spectracom Default Login
**Template ID:** spectracom-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`spectracom-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Spectracom default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /users/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

data%5Bbutton%5D=submit&data%5BUser%5D%5Busername%5D={{username}}&data%5BUser%5D%5Bpassword%5D={{password}}
```

## References
- https://orolia.com/manuals/NC/Content/NC_and_SS/Com/Topics/ADMIN/Passwords.htm
