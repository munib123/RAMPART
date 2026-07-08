# Vulnerability: WordPress WP Super Cache - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-super-cache-fpd.yaml`)

## Description
WordPress WP Super Cache plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-super-cache/ossdl-cdn.php
GET {{BaseURL}}/wp-content/plugins/wp-super-cache/rest/load.php
```

