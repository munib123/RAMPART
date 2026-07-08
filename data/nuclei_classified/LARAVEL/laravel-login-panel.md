# Vulnerability: Laravel Login - Panel Detection
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-login-panel.yaml`)

## Description
A Laravel login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/login
GET {{BaseURL}}/authentication/login
GET {{BaseURL}}/login
```

