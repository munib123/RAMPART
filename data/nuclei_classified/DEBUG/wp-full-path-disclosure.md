# Vulnerability: Wordpress - Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-full-path-disclosure.yaml`)

## Description
Wordpress internal file system path of a WordPress installation is exposed or disclosed to unauthorized users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-includes/rss-functions.php
```

