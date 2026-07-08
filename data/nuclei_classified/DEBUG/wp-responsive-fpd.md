# Vulnerability: WordPress Coming Soon Page - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-responsive-fpd.yaml`)

## Description
WordPress Coming Soon Page & Maintenance Mode plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/responsive-coming-soon/responsive-coming-soon.php
```

