# Vulnerability: FastCGI Configuration - File Disclosure
**Classification:** FASTCGI
**Source:** Nuclei Template (`fastcgi-config.yaml`)

## Description
FastCGI configuration file is exposed and accessible, potentially leading to sensitive information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fastcgi.conf
GET {{BaseURL}}/config/fastcgi.conf
```

