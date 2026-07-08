# Vulnerability: phpunit.xml File Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`phpunit.yaml`)

## Description
Phpunit.xml was created by Romain Bourdon for the development of WampServer 3.1. Phpunit.xml is packaged with WampServer 3.1.9 and XAMPP 5.6.40.

## Secure Mitigation
Ensure the approved and updated version is installed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phpunit.xml
```

