# Vulnerability: WordPress Data Source for Contact Form 7 - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-cf7-data-source-fpd.yaml`)

## Description
WordPress Plugin CData Source for Contact Form 7 files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/cf7-data-source/cf7-datasource.php
```

