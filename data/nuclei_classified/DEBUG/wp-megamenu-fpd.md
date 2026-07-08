# Vulnerability: WordPress Plugin Max Mega Menu (megamenu) - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-megamenu-fpd.yaml`)

## Description
WordPress Plugin Max Mega Menu plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/megamenu/integration/zerif/functions.php
```

