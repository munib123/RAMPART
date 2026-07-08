# Vulnerability: PHP_CodeSniffer Configuration Exposure - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`phpcs-config.yaml`)

## Description
PHP_CodeSniffer configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/phpcs.xml
```

