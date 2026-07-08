# Vulnerability: WordPress Twenty Sixteen - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-twentysixteen-fpd.yaml`)

## Description
WordPress Twenty Sixteen theme files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/twentysixteen/functions.php
```

