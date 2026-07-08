# Vulnerability: WordPress Twenty Seventeen - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-twenty-theme-fpd.yaml`)

## Description
WordPress Twenty Seventeen theme files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/twentyseventeen/inc/template-tags.php
GET {{BaseURL}}/wp-content/themes/twentyseventeen/inc/
```

