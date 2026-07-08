# Vulnerability: WordPress Plugin iThemes Security - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-better-wp-security-fpd.yaml`)

## Description
WordPress Plugin iThemes Security files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/better-wp-security/core/admin-pages/page-logs.php
```

