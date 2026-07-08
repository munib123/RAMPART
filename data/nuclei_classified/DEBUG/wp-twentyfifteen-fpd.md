# Vulnerability: WordPress Twenty Fifteen Theme - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-twentyfifteen-fpd.yaml`)

## Description
WordPress theme twentyfifteen internal file system path of a WordPress installation is exposed or disclosed to unauthorized users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/twentyfifteen/functions.php
```

