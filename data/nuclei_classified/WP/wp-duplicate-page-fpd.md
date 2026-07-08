# Vulnerability: WordPress Duplicate Page - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-duplicate-page-fpd.yaml`)

## Description
WordPress Plugin Duplicate Page files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/duplicate-page/duplicatepage.php
```

