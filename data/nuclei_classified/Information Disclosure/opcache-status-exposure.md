# Nuclei Template: OPcache Status Page - Detect
**Template ID:** opcache-status-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`opcache-status-exposure.yaml`)

## Vulnerability Information & PoC

## Description
OPcache status page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/opcache-status/
GET {{BaseURL}}/php-opcache-status/
GET {{BaseURL}}/opcache-status/opcache.php
```

## References
- https://www.php.net/manual/en/book.opcache.php
