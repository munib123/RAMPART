# Nuclei Template: phpmyadmin Data Exposure
**Template ID:** phpmyadmin-misconfiguration
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`phpmyadmin-misconfiguration.yaml`)

## Vulnerability Information & PoC

## Description
An unauthenticated instance of phpmyadmin was discovered, which could be leveraged to access sensitive information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/phpmyadmin/index.php?db=information_schema
GET {{BaseURL}}/phpMyAdmin/index.php?db=information_schema
```

## References
- https://www.exploit-db.com/ghdb/6997
