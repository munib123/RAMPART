# Vulnerability: WordPress Advanced Responsive Video Embedder - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-advanced-responsive-video-embedder-fpd.yaml`)

## Description
WordPress Advanced Responsive Video Embedder plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/advanced-responsive-video-embedder/php/init.php
GET {{BaseURL}}/wp-content/plugins/advanced-responsive-video-embedder/advanced-responsive-video-embedder.php
```

