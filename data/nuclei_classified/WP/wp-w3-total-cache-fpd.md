# Vulnerability: WordPress W3 Total Cache - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-w3-total-cache-fpd.yaml`)

## Description
WordPress W3 Total Cache plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/w3-total-cache/inc/lightbox/purchase.php
```

