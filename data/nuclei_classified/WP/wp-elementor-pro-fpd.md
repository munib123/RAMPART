# Vulnerability: WordPress Elementor Pro - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-elementor-pro-fpd.yaml`)

## Description
WordPress Plugin Elementor Pro plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/elementor-pro/modules/notes/notifications/views/email.php
```

