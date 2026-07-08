# Vulnerability: PHP Composer Binary - Exposure
**Classification:** PHP
**Source:** Nuclei Template (`php-composer-binary.yaml`)

## Description
This Nuclei template checks if the specified endpoints have publically accessible PHP Composer Binary.

## Secure Mitigation
Restrict access to the PHP Composer binary by implementing proper access controls and permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/composer
```

