# Vulnerability: cPanel Configuration - File Disclosure
**Classification:** CPANEL
**Source:** Nuclei Template (`cpanel-config.yaml`)

## Description
cPanel configuration file is exposed and accessible, potentially leading to sensitive information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cpanel.config
```

