# Vulnerability: WordPress WooCommerce - Directory Search
**Classification:** EDB
**Source:** Nuclei Template (`wordpress-woocommerce-listing.yaml`)

## Description
WordPress WooCommerce plugin sensitive directory searches were conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/woocommerce/
```

