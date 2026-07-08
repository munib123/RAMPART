# Vulnerability: WordPress Plugin Google Tag Manager - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-duracelltomi-google-tag-manager-fpd.yaml`)

## Description
WordPress Plugin Google Tag Manager files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/duracelltomi-google-tag-manager/admin/admin.php
```

