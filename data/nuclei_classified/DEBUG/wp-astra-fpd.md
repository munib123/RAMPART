# Vulnerability: WordPress Astra - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-astra-fpd.yaml`)

## Description
WordPress Astra Theme files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/astra/assets/svg/logo-svg-icons/icons-v6-0.php
GET {{BaseURL}}/wp-content/themes/astra/inc/addons/scroll-to-top/class-astra-scroll-to-top.php
```

