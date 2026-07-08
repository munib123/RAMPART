# Vulnerability: Dialogic XMS Admin Console - Default Login
**Classification:** DIALOGIC
**Source:** Nuclei Template (`dialogic-xms-default-login.yaml`)

## Description
Dialogic XMS Admin Console was using default credentials and it was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.php/verifyLogin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

usernameId={{username}}&passwordId={{password}}
```

