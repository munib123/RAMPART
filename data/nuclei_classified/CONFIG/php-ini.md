# Vulnerability: Php.ini File Disclosure
**Classification:** CONFIG
**Source:** Nuclei Template (`php-ini.yaml`)

## Description
php.ini file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/php.ini
```

