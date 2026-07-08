# Vulnerability: WordPress Menu Image - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-menu-image-fpd.yaml`)

## Description
WordPress Plugin Menu Image plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/menu-image/freemius/templates/checkout.php
```

