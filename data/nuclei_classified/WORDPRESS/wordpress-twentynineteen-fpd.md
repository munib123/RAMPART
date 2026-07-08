# Vulnerability: WordPress Twenty Nineteen - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-twentynineteen-fpd.yaml`)

## Description
The WordPress Twentytwenty themes was detected to be vulnerable to Full Path Disclosure, allowing unauthenticated access to the full application path.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/twentynineteen/functions.php
```

