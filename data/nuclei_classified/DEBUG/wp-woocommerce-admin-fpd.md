# Vulnerability: WordPress Plugin WooCommerce Admin (woocommerce-admin) Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-woocommerce-admin-fpd.yaml`)

## Description
WordPress Plugin WooCommerce Admin plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/woocommerce-admin/src/Loader.php
```

