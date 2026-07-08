# Vulnerability: WordPress Plugin Intuitive Custom Post Order - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-intuitive-custom-post-order-fpd.yaml`)

## Description
WordPress Widget Logic plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/intuitive-custom-post-order/admin/settings.php
GET {{BaseURL}}/wp-content/plugins/intuitive-custom-post-order/admin/settings-network.php
```

