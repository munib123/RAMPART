# Vulnerability: WordPress Twenty Twenty Theme - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-twentytwenty-fpd.yaml`)

## Description
WordPress theme twentytwenty internal file system path of a WordPress installation is exposed or disclosed to unauthorized users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/twentytwenty/functions.php
```

