# Nuclei Template: DVWA Default Login
**Template ID:** dvwa-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** Critical
**CWE:** CWE-798
**Source:** Nuclei Template (`dvwa-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Damn Vulnerable Web App (DVWA) is a test application for security professionals. The hard coded credentials are part of a security testing scenario.

## Steps to reproduce / Exploit Payload
```http
GET /login.php HTTP/1.1
Host: {{Hostname}}
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID={{session}}; security=low
Connection: close

username={{username}}&password={{password}}&Login=Login&user_token={{token}}
```

## References
- https://opensourcelibs.com/lib/dvwa
