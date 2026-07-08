# Vulnerability: OPcache Status Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opcache-status-exposure.yaml`)

## Description
OPcache status page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/opcache-status/
GET {{BaseURL}}/php-opcache-status/
GET {{BaseURL}}/opcache-status/opcache.php
```

