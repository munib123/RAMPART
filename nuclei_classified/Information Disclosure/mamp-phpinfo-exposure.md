# Nuclei Template: MAMP - PHP Info Exposure
**Template ID:** mamp-phpinfo-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`mamp-phpinfo-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected MAMP server was exposed phpinfo() page, revealing sensitive PHP configuration, server paths, and environment variables.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/MAMP/phpinfo.php
```

## References
- https://www.mamp.info/
- https://www.acunetix.com/vulnerabilities/web/phpinfo-pages/
