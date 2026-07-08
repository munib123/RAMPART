# Vulnerability: WordPress Plugin SSL Insecure Content Fixer - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-ssl-insecure-content-fixer-fpd.yaml`)

## Description
WordPress SSL Insecure Content Fixer plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/ssl-insecure-content-fixer/includes/nonces.php
GET {{BaseURL}}/wp-content/plugins/ssl-insecure-content-fixer/nowp/ajax.php
```

