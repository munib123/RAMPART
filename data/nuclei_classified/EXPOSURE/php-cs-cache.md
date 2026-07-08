# Vulnerability: PHP-CS-Fixer Cache - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`php-cs-cache.yaml`)

## Description
PHP CS fixer cache internal file is disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.php_cs.cache
```

