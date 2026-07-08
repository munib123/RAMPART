# Vulnerability: phpmyadmin Data Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`phpmyadmin-misconfiguration.yaml`)

## Description
An unauthenticated instance of phpmyadmin was discovered, which could be leveraged to access sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phpmyadmin/index.php?db=information_schema
GET {{BaseURL}}/phpMyAdmin/index.php?db=information_schema
```

