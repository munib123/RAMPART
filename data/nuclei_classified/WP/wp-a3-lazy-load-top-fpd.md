# Vulnerability: WordPress a3 Lazy Load - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-a3-lazy-load-top-fpd.yaml`)

## Description
WordPress Plugin a3 Lazy Load plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/a3-lazy-load/a3-lazy-load.php
GET {{BaseURL}}/wp-content/plugins/a3-lazy-load/admin/a3-lazy-load-admin.php
```

