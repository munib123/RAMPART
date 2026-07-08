# Vulnerability: Composer Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`composer-config.yaml`)

## Description
Composer configuration file detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/composer.json
GET {{BaseURL}}/composer.lock
GET {{BaseURL}}/.composer/composer.json
GET {{BaseURL}}/vendor/composer/installed.json
```

