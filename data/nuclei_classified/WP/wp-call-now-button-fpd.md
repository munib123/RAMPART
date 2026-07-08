# Vulnerability: WordPress Call Now Button - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-call-now-button-fpd.yaml`)

## Description
WordPress Plugin Call Now Button files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/call-now-button/call-now-button.php
GET {{BaseURL}}/wp-content/plugins/call-now-button/src/renderers/noop/class-nooprenderer.php
```

