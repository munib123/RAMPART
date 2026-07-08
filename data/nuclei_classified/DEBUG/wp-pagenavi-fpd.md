# Vulnerability: WordPress WP-PageNavi - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-pagenavi-fpd.yaml`)

## Description
WordPress WP-PageNavi plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-pagenavi/admin.php
GET {{BaseURL}}/wp-content/plugins/wp-pagenavi/wp-pagenavi.php
```

