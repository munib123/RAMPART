# Vulnerability: WordPress OceanWP - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-oceanwp-fpd.yaml`)

## Description
WordPress OceanWP theme is vulnerable to full path disclosure via direct access to theme files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/oceanwp/inc/helpers.php
GET {{BaseURL}}/wp-content/themes/oceanwp/inc/customizer/customizer.php
GET {{BaseURL}}/wp-content/themes/oceanwp/inc/walker/menu-walker.php
```

