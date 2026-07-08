# Vulnerability: Symfony Debug Mode
**Classification:** SYMFONY
**Source:** Nuclei Template (`symfony-debug.yaml`)

## Description
A Symfony installations 'debug' interface is enabled, allowing the disclosure and possible execution of arbitrary code.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/admin_dev.php
GET {{BaseURL}}/index_dev.php
GET {{BaseURL}}/app_dev.php
```

