# Vulnerability: WordPress WPFront Scroll Top - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-wpfront-scroll-top-fpd.yaml`)

## Description
WordPress Plugin WPFront Scroll Top plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wpfront-scroll-top/wpfront-scroll-top.php
```

