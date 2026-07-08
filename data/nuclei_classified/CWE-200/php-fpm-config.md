# Vulnerability: PHP-FPM Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`php-fpm-config.yaml`)

## Description
PHP-FPM configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/php-fpm.conf
```

