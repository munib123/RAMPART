# Vulnerability: MAMP - PHP Info Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`mamp-phpinfo-exposure.yaml`)

## Description
Detected MAMP server was exposed phpinfo() page, revealing sensitive PHP configuration, server paths, and environment variables.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/MAMP/phpinfo.php
```

