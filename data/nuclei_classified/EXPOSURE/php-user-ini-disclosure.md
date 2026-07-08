# Vulnerability: Php User.ini Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`php-user-ini-disclosure.yaml`)

## Description
PHP user.ini file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user.ini
GET {{BaseURL}}/.user.ini
```

