# Vulnerability: WordPress WPForms - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-wpforms-lite-fpd.yaml`)

## Description
WordPress Plugin WPForms files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wpforms-lite/src/Frontend/Modern.php
```

