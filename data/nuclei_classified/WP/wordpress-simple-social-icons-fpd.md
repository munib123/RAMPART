# Vulnerability: WordPress Simple Social Icons - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-simple-social-icons-fpd.yaml`)

## Description
WordPress Plugin Simple Social Icons files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/simple-social-icons/simple-social-icons.php
```

