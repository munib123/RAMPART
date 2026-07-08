# Vulnerability: WordPress Ajax Search Lite - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-ajax-search-lite-fpd.yaml`)

## Description
WordPress Plugin Ajax Search Lite files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/ajax-search-lite/includes/classes/widgets/class-search-widget.php
```

