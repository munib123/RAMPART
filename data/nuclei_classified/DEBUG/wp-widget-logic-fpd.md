# Vulnerability: WordPress Widget Logic - Full Path Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-widget-logic-fpd.yaml`)

## Description
WordPress Widget Logic plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/widget-logic/widget_logic_admin_options.php
GET {{BaseURL}}/wp-content/plugins/widget-logic/widget-logic.php
```

