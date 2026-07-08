# Vulnerability: WordPress Joinchat - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-joinchat-fpd.yaml`)

## Description
WordPress Plugin Joinchat files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/creame-whatsapp-me/includes/class-joinchat-elementor-finder.php
```

