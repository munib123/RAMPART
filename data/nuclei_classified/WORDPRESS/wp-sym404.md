# Vulnerability: Wordpress sym404 directory
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-sym404.yaml`)

## Description
Searches for sensitive directories present in the sym404.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-includes/sym404/root/etc/passwd
```

